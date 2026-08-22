# A step is over when nothing of it is still running, not when the command it
# started exits. Docker gets that from the pid namespace it tears down, and so
# do the CD_USE_NS / CD_USE_ISOLATION paths here, where the holder is pid 1 of
# a namespace that dies with the session. The default path has neither: a
# `RUN cmd &` or a `RUN service x start` left a process writing into the stage
# rootfs while the "after" snapshot was being taken -- which makes a layer that
# differs from run to run -- kept the bind mounts busy so the teardown could not
# unmount them, and left a daemon running long after the build. _stop_step()
# closes both halves of that: the process group the step leads, and the
# descendants that daemonise out of it, which land back on this process because
# it makes itself a child subreaper first.

import contextlib
import ctypes
import functools
import os
import signal
import subprocess
import time
import typing

from chroot_distro import dirfd
from chroot_distro.atomic import publish_file
from chroot_distro.constants import (
    DEFAULT_PATH_ENV,
)
from chroot_distro.helpers.build_cache import (
    compute_recipe_hash,
)
from chroot_distro.helpers.build_cache import (
    lookup as cache_lookup,
)
from chroot_distro.helpers.build_cache import (
    record as cache_record,
)
from chroot_distro.helpers.build_engine.constants import PREDEFINED_ARGS
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.run_mounts import (
    RunMount,
    run_mount_session,
    validate_and_parse_run_flags,
)
from chroot_distro.helpers.build_engine.users import resolve_user_for_chroot
from chroot_distro.helpers.docker import apply_layer, layer_cache_path
from chroot_distro.helpers.layer_diff import (
    diff_snapshots,
    snapshot,
    write_layer_tar,
)
from chroot_distro.helpers.tar_extract import _safe_resolve
from chroot_distro.message import log_info, warn


def do_run(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """RUN <cmd>: execute command under chroot and snapshot the diff into a layer.

    Cache lookup happens first: a recipe-hash hit applies the cached
    layer and skips chroot entirely. On a miss, snapshot the rootfs,
    exec under chroot, snapshot again, pack the delta into a gzipped
    OCI layer, and record the (recipe-hash → layer) entry.
    """
    stage = engine.current

    # Validate flags before the cache lookup: unsupported flags must be
    # rejected even when the layer is cached.
    mounts = validate_and_parse_run_flags(instr)

    if instr["exec_form"]:
        command = list(instr["value"])
        stdin_input = None
    else:
        heredocs = instr.get("heredocs") or []
        if heredocs:
            body = "\n".join(hd["body"] for hd in heredocs)
            command = [*list(stage.shell), body]
        else:
            command = [*list(stage.shell), str(instr["value"])]
        stdin_input = None

    # Cache lookup.
    extra = _run_extra_inputs(engine)
    recipe = compute_recipe_hash(stage.parent_layer_digest, instr, extra_inputs=extra)
    if not engine.no_cache:
        hit = cache_lookup(recipe)
        if hit is not None:
            cached_path = layer_cache_path(hit["layer_digest"])
            if os.path.isfile(cached_path):
                engine.report_cache_hit(instr)
                apply_layer(cached_path, stage.rootfs_dir)
                stage.layers.append(
                    {
                        "digest": hit["layer_digest"],
                        "size": hit["size"],
                        "diff_id": hit["diff_id"],
                    }
                )
                stage.parent_layer_digest = hit["layer_digest"]
                return

    engine.log("Indexing rootfs state...")
    before = snapshot(stage.rootfs_dir)
    exit_code = _exec_chroot(engine, stage, command, stdin_input, mounts)
    if exit_code != 0:
        raise BuildError(f"RUN command failed at line {instr['lineno']} with exit code {exit_code}.")

    engine.log("Capturing filesystem changes...")
    after = snapshot(stage.rootfs_dir)
    added, modified, deleted = diff_snapshots(before, after)
    paths_to_pack = added + modified

    if not (paths_to_pack or deleted):
        engine.log("No filesystem changes; emitting an empty layer.")
    else:
        engine.log(f"Packing layer: {len(added)} added, {len(modified)} modified, {len(deleted)} deleted...")

    tmp_layer_path = os.path.join(engine.tmp_root, f"layer-{stage.index}-{len(stage.layers)}.tar.gz")
    digest, size, diff_id = write_layer_tar(
        stage.rootfs_dir,
        paths_to_pack,
        deleted,
        tmp_layer_path,
    )
    # Published through the same walk every other cache writer uses:
    # os.makedirs(dirname) plus os.replace(tmp, final) resolved the layer cache
    # by name, so a planted `oci_layers -> <host dir>` collected what a build
    # produced.
    publish_file(tmp_layer_path, layer_cache_path(digest))

    stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
    stage.parent_layer_digest = digest
    cache_record(recipe, digest, diff_id, size, {})


def _run_extra_inputs(engine: typing.Any) -> str:
    """Encode env + ARG state visible to RUN for the recipe hash."""
    scope = engine.expansion_scope()
    items = sorted(scope.items())
    return "\n".join(f"{k}={v}" for k, v in items)


def _exec_chroot(
    engine: typing.Any,
    stage: typing.Any,
    command: list[str],
    stdin_input: str | None,
    mounts: list[RunMount] | None = None,
) -> int:
    """Invoke chroot against *stage*'s rootfs to execute *command*."""
    rootfs = stage.rootfs_dir

    from chroot_distro.commands.login.chroot_cmd import build_chroot_args
    from chroot_distro.commands.login.passwd import find_user_groups

    uid, gid = resolve_user_for_chroot(rootfs, stage.user)

    user_name = stage.user or "root"
    user_spec = user_name if not user_name.isdigit() else str(uid)
    groups = find_user_groups(rootfs, user_spec, str(gid))

    chroot_args = build_chroot_args(
        rootfs=rootfs,
        login_uid=str(uid) if uid else None,
        login_gid=str(gid) if gid else None,
        groups=groups,
        workdir=stage.workdir or "/",
        inner_cmd=command,
    )

    child_env = _build_child_env(stage)

    if not engine.quiet and not engine.verbose:
        log_info(f"Running step (user={stage.user or 'root'}, cwd={stage.workdir or '/'})...")

    # Isolated builds (CD_USE_ISOLATION → max, CD_USE_NS → ns): run the step
    # inside a namespace holder. "max" also chroots the holder into the
    # rootfs so it cannot see host processes/mounts; "ns" keeps the default
    # mount set. Heredoc/stdin steps and kernels without mount-namespace
    # support fall back to the plain host-namespace path below.
    if engine.isolation_mode in ("ns", "max") and stdin_input is None:
        from chroot_distro.helpers import isolation

        container_key = f"build_{os.path.basename(engine.tmp_root)}_{stage.index}"
        session = (
            isolation.max_isolation_session
            if engine.isolation_mode == "max"
            else isolation.namespace_session
        )
        with session(container_key, rootfs, minimal=True) as holder:
            if holder is not None:
                with run_mount_session(engine, stage, mounts or [], holder=holder) as extra_env:
                    return _run_in_holder(holder, chroot_args, {**child_env, **extra_env})
            return _run_plain(rootfs, chroot_args, child_env, stdin_input, engine, stage, mounts or [])

    return _run_plain(rootfs, chroot_args, child_env, stdin_input, engine, stage, mounts or [])


def _run_in_holder(holder: typing.Any, chroot_args: list[str], child_env: dict[str, str]) -> int:
    """Execute *chroot_args* inside the holder's namespaces; return the exit code.

    The holder is already chrooted into the rootfs (maximum isolation); the
    child enters its mount/PID/UTS/IPC namespaces via ``nsenter`` and inherits
    the build's stdio so RUN output streams live.
    """
    try:
        result = holder.run(chroot_args, env=child_env)
    except FileNotFoundError as exc:
        raise BuildError(f"chroot command execution failed: {exc}") from exc
    return int(result.returncode)


def _mount_point(rootfs: str, guest_path: str) -> str | None:
    """Make the directory *guest_path* names inside *rootfs*. Path, or None.

    A bind target is a name, and os.makedirs(exist_ok=True) accepts a symlink
    to a directory while mount(2) resolves the name all over again. Every
    component of one of these is image content and the step's binds are applied
    in the host's mount namespace, so an image shipping `dev -> <host dir>` had
    the host's own /dev mounted onto that directory, `dev/pts` created inside
    it, and the mount left behind afterwards -- unmount_all() sweeps what is
    under the rootfs, and this is not.

    The path is resolved the way the guest sees it, with an absolute link
    target re-anchored at the rootfs and ".." unable to climb out of it, and
    then made a level at a time off a descriptor. `/dev/shm -> /run/shm` is
    still followed; nothing outside the rootfs can be created or mounted on.
    None means the name would not validate, and the caller leaves the bind off.
    """
    parts = [p for p in guest_path.split("/") if p not in ("", os.curdir)]
    resolved = _safe_resolve(rootfs, parts)
    if resolved is None:
        return None
    rel = os.path.relpath(resolved, rootfs)
    return dirfd.makedirs_under(rootfs, [] if rel == os.curdir else rel.split(os.sep))


def _run_plain(
    rootfs: str,
    chroot_args: list[str],
    child_env: dict[str, str],
    stdin_input: str | None,
    engine: typing.Any = None,
    stage: typing.Any = None,
    mounts: list[RunMount] | None = None,
) -> int:
    """Execute *chroot_args* with host-namespace bind mounts (no isolation)."""
    import chroot_distro.helpers.mount_manager as mount_manager
    from chroot_distro.commands.login import bindings

    resolved_binds, _ = bindings.get_bindings(rootfs=rootfs, minimal=True)

    # Pre-clean stale mounts if any
    with contextlib.suppress(Exception):
        mount_manager.unmount_all(rootfs)

    try:
        for src, dst in resolved_binds:
            guest_path = "/" + os.path.relpath(dst, rootfs)
            target = _mount_point(rootfs, guest_path)
            if target is None:
                warn(f"rootfs {guest_path} is not a plain directory; running this step without that bind.")
                continue
            is_run = os.path.realpath(target) == os.path.realpath(os.path.join(rootfs, "run"))
            mount_manager.safe_mount(src, target, recursive=is_run)

        # RUN --mount targets go on top of the base binds (and are torn down
        # before them when the `with` block exits).
        with run_mount_session(engine, stage, mounts or []) as extra_env:
            stdin_arg = subprocess.PIPE if stdin_input is not None else subprocess.DEVNULL
            # Before anything is spawned, so a descendant that outlives its own
            # parent is reparented here rather than onto init.
            _become_subreaper()
            baseline = set(_adopted())
            proc = subprocess.Popen(
                chroot_args,
                env={**child_env, **extra_env},
                stdin=stdin_arg,
                start_new_session=True,
            )
            try:
                if stdin_input is not None:
                    proc.communicate(input=stdin_input.encode())
                else:
                    proc.wait()
            except KeyboardInterrupt:
                with contextlib.suppress(OSError):
                    os.killpg(proc.pid, signal.SIGTERM)
                proc.wait()
                _stop_step(proc.pid, baseline, quiet=True)
                raise
            _stop_step(proc.pid, baseline, quiet=engine is not None and engine.quiet)
            return proc.returncode
    except FileNotFoundError as exc:
        raise BuildError(f"chroot command execution failed: {exc}") from exc
    finally:
        # Clean up mounts
        mount_manager.unmount_all(rootfs)


# How often a leftover is looked at again, and how long it gets to take a
# SIGTERM before the SIGKILL.
_STEP_POLL_INTERVAL = 0.05
_STRAY_GRACE_SECONDS = 2.0

# prctl(2), Linux 3.4 and up, Android included.
_PR_SET_CHILD_SUBREAPER = 36

@functools.lru_cache(maxsize=1)
def _become_subreaper() -> bool:
    """Ask the kernel to reparent orphaned descendants onto this process.

    This is what makes a step's leftovers findable at all. A backgrounded
    command outlives the shell that started it and a daemon goes further --
    fork, setsid, fork, which leaves the step's process group as well -- and
    either way the process is then no relation of ours that any interface will
    name. As a subreaper it is reparented here instead of onto init, so
    /proc/self/task/<pid>/children lists it.

    Asked once, best effort: a kernel (or a seccomp filter) that refuses leaves
    _stop_step with nothing but the process group to look at.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return bool(libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0)
    except (OSError, AttributeError, ValueError):
        return False


def _children_of(pid: int) -> list[int]:
    """The PIDs the kernel currently calls children of *pid*."""
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as fh:
            data = fh.read()
    except OSError:
        return []
    return [int(tok) for tok in data.split() if tok.isdigit()]


def _adopted(baseline: typing.Container[int] = (), skip_pid: int | None = None) -> list[int]:
    """The step's descendants the kernel has reparented onto this process.

    *baseline* is what was already there when the step started, which should be
    nothing -- the previous step is stopped before the next one begins -- but a
    straggler that would not die must not be counted against every step that
    follows it.
    """
    return [pid for pid in _children_of(os.getpid()) if pid != skip_pid and pid not in baseline]


def _group_members(pgid: int, skip: typing.Container[int] = ()) -> list[int]:
    """The PIDs in process group *pgid*, minus *skip*.

    Read out of /proc rather than signalled as a group, so the caller can leave
    the step's own process out of it and report on what it found. The parse
    takes the fields after the last ')', since a comm can hold anything at all,
    including one.
    """
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    members = []
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid in skip:
            continue
        try:
            with open(f"/proc/{pid}/stat") as fh:
                data = fh.read()
        except OSError:
            continue
        try:
            fields = data[data.rindex(")") + 1 :].split()
            if int(fields[2]) == pgid:
                members.append(pid)
        except (ValueError, IndexError):
            continue
    return members


def _signal_leftovers(targets: list[int], sig: int) -> None:
    """Deliver *sig* to each leftover, and to any group it leads.

    A daemonised leftover called setsid, so it leads a group of its own and
    that group goes too -- otherwise its children outlive it by a generation.
    killpg(pid) can only ever reach a group led by that very process, a group id
    being the pid of its leader, so this cannot reach anything the step did not
    start.
    """
    for pid in targets:
        with contextlib.suppress(OSError):
            os.kill(pid, sig)
        with contextlib.suppress(OSError):
            os.killpg(pid, sig)


def _reap(pids: list[int]) -> None:
    """Collect the leftovers that have exited, so none linger as zombies.

    Named one at a time rather than with waitpid(-1), which could take the
    status of something this process is waiting on elsewhere. A leftover reaped
    a moment too early to be a zombie is collected on the next round of the
    sweep, or left to the next step, which knows what was already there and
    does not count it again.
    """
    for pid in pids:
        with contextlib.suppress(OSError, ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


def _leftovers(pgid: int | None, baseline: typing.Container[int], skip_pid: int | None) -> list[int]:
    """Every process the step still has running, most-derived first.

    This process and the group it is in are never among them. A step runs in a
    session of its own, so its group id can only be the step's; one that is
    this program's own group means the caller got the pgid wrong, and the answer
    to that must not be a SIGTERM to everything sharing a terminal with the
    build.
    """
    found = list(_adopted(baseline, skip_pid=skip_pid))
    skip = set(found)
    skip.add(os.getpid())
    if skip_pid is not None:
        skip.add(skip_pid)
    if pgid is not None and pgid != os.getpgrp():
        found.extend(_group_members(pgid, skip=skip))
    return found


def _stop_step(pgid: int | None, baseline: typing.Container[int] = (), *, quiet: bool = False) -> int:
    """Stop whatever the step still has running. Returns how many it found.

    Costs one small /proc read when the step ended cleanly, which is the usual
    case; only a step that left something behind pays for the /proc scan.
    """
    targets = _leftovers(pgid, baseline, None)
    if not targets:
        return 0

    found = len(targets)
    _signal_leftovers(targets, signal.SIGTERM)
    deadline = time.monotonic() + _STRAY_GRACE_SECONDS
    while time.monotonic() < deadline:
        _reap(targets)
        targets = _leftovers(pgid, baseline, None)
        if not targets:
            break
        time.sleep(_STEP_POLL_INTERVAL)

    targets = _leftovers(pgid, baseline, None)
    if targets:
        _signal_leftovers(targets, signal.SIGKILL)
        _reap(targets)

    if not quiet:
        warn(
            f"the step left {found} process(es) running after its command finished; "
            "they were stopped, so the layer captures a settled rootfs."
        )
    return found


def _build_child_env(stage: typing.Any) -> dict[str, str]:
    env = {}
    env["PATH"] = stage.env.get("PATH") or DEFAULT_PATH_ENV
    env["HOME"] = stage.env.get("HOME", "/root")
    env["TERM"] = os.environ.get("TERM", "") or "xterm-256color"
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm

    # Predefined ARGs from the host environment (proxies etc.) are
    # passed through even if the Dockerfile didn't declare them.
    for k in PREDEFINED_ARGS:
        v = os.environ.get(k, "")
        if v:
            env[k] = v

    # Declared ARGs in this stage.
    for k in stage.declared_args:
        if k in stage.args:
            env[k] = stage.args[k]

    # ENVs always win.
    for k, v in stage.env.items():
        env[k] = v

    # Clean up dangerous env vars
    env.pop("LD_PRELOAD", None)
    return env
