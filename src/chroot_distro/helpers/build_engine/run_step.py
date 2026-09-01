# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""RUN: execute one step under chroot and pack what it changed into a layer.

Cache first: a recipe-hash hit applies the cached layer and never enters a
chroot. On a miss the rootfs is snapshotted, the command runs, the rootfs is
snapshotted again, and the delta becomes a gzipped OCI layer, published into the
layer cache through the same O_NOFOLLOW walk every other cache writer uses.

`_run_extra_inputs` is what that hash is worth: the instruction text says what
the command is, and this says what it is being run against. Its own docstring
lists the inputs and why each one is there, since a missing one is a layer built
for another platform, or from another context, served as this step's.

`_step_command` is where a here-doc becomes a command, and it draws the three
lines BuildKit draws: a lone `RUN <<EOF` runs its body as the shell's script, one
whose body opens with a shebang becomes a file the kernel runs through the
interpreter it names, and anything else (a redirect into a command, several
bodies) is handed to the shell reassembled, since the shell is what reads a
here-doc in the first place.

A step is over when nothing of it is still running, not when the command it
started exits. Docker gets that from the pid namespace it tears down, and so do
the CD_USE_NS and CD_USE_ISOLATION paths here, where the holder is pid 1 of a
namespace that dies with the session. The default path has neither: a `RUN cmd &`
or a `RUN service x start` left a process writing into the stage rootfs while the
"after" snapshot was taken, which makes a layer that differs from run to run,
keeps the binds busy so teardown cannot unmount them, and leaves a daemon running
long after the build. `_stop_step` closes both halves of that, the process group
the step leads and the descendants that daemonise out of it, which land back on
this process because it makes itself a child subreaper first.

`_exec_chroot` picks between a max isolation holder, a namespace holder and the
plain host-namespace bind set; a step with stdin and a kernel without
mount-namespace support both fall back to the plain path. Either way the
chroot happens in the child, as the last thing before the exec so the namespaces
are already joined, and onto the stage's pinned descriptor where there is one.
`_require_emulator` gates all of it: `build`'s preflight only sees the Dockerfile's
own RUN lines, so a foreign-arch step with no binfmt_misc handler is refused here
instead, which is also what leaves a cached foreign step working (nothing execs for
a cache hit).

The plain path applies its binds from the host's mount namespace, so every target
is a name an image chose: `_mount_point` resolves one the way the guest sees it,
because makedirs accepts a symlink to a directory and mount(2) then resolves the
name all over again, so `dev -> <host dir>` had the host's own /dev mounted there
and left behind.

`_refuse_host_exec` keeps an `LD_*` value out of a step's environment when it
came from an ENV line or a declared ARG. The invoking user's environment is not
filtered and the value still stands in the image config: provenance is the whole
rule, and `constants.is_host_exec_var` states it.
"""

import contextlib
import ctypes
import functools
import os
import re
import signal
import time
import typing

from chroot_distro import dirfd
from chroot_distro.arch import needs_emulation
from chroot_distro.atomic import publish_file
from chroot_distro.constants import (
    DEFAULT_PATH_ENV,
)
from chroot_distro.helpers.binfmt import ensure_handler
from chroot_distro.helpers.build_cache import (
    compute_recipe_hash,
)
from chroot_distro.helpers.build_cache import (
    lookup as cache_lookup,
)
from chroot_distro.helpers.build_cache import (
    record as cache_record,
)
from chroot_distro.helpers.build_engine.constants import PREDEFINED_ARGS, is_host_exec_var
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.run_mounts import (
    RunMount,
    mount_cache_inputs,
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
from chroot_distro.syscalls.chroot import (
    _try_exec,
    _wait_for_child,
    _wait_for_child_with_signals,
    enter_chroot,
)


def _rootfs_fd(stage: typing.Any) -> int:
    """A caller-owned descriptor on *stage*'s rootfs.

    Re-opened from the stage's pin when it has one, so what is written is the
    tree the stage was created against; opened by name only for a stage some
    caller built itself.
    """
    if stage.rootfs_fd is not None:
        return dirfd.reopen(stage.rootfs_fd)
    return dirfd.opendir(stage.rootfs_dir)


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

    command, script = _step_command(stage, instr)

    extra = _run_extra_inputs(engine, stage, mounts)
    recipe = compute_recipe_hash(stage.parent_layer_digest, instr, extra_inputs=extra)
    engine.step_recipes.add(recipe)
    if not engine.no_cache:
        hit = cache_lookup(recipe)
        if hit is not None:
            cached_path = layer_cache_path(hit["layer_digest"])
            if os.path.isfile(cached_path):
                engine.report_cache_hit(instr)
                rootfs_fd = _rootfs_fd(stage)
                try:
                    apply_layer(cached_path, rootfs_fd)
                finally:
                    os.close(rootfs_fd)
                stage.layers.append(
                    {
                        "digest": hit["layer_digest"],
                        "size": hit["size"],
                        "diff_id": hit["diff_id"],
                    }
                )
                stage.parent_layer_digest = hit["layer_digest"]
                return

    if script is not None:
        _write_step_script(stage, *script)

    engine.log("Indexing rootfs state...")
    before = snapshot(stage.rootfs_dir, rootfs_fd=stage.rootfs_fd)
    exit_code = _exec_chroot(engine, stage, command, None, mounts)
    if script is not None:
        # Out of the tree, and out of the snapshot that recorded it, so the
        # script the step ran is in neither this layer nor a later step's.
        _remove_step_script(stage, script[0])
        before.pop(script[0], None)
    if exit_code != 0:
        raise BuildError(f"RUN command failed at line {instr['lineno']} with exit code {exit_code}.")

    engine.log("Capturing filesystem changes...")
    after = snapshot(stage.rootfs_dir, rootfs_fd=stage.rootfs_fd)
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
        rootfs_fd=stage.rootfs_fd,
    )
    # Published through the same walk every other cache writer uses:
    # os.makedirs(dirname) plus os.replace(tmp, final) resolved the layer cache
    # by name, so a planted `oci_layers -> <host dir>` collected what a build
    # produced.
    publish_file(tmp_layer_path, layer_cache_path(digest))

    stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
    stage.parent_layer_digest = digest
    cache_record(recipe, digest, diff_id, size, {})


# The whole of a command line that is nothing but a here-doc opener, which is
# the form that runs its body rather than being handed to the shell as written.
_BARE_HEREDOC_RE = re.compile(r"""^\d*<<-?\s*(["']?)[A-Za-z_][A-Za-z0-9_]*\1$""")


def _step_command(stage: typing.Any, instr: dict[str, typing.Any]) -> tuple[list[str], tuple[str, str] | None]:
    """What this step runs: (argv, the script to plant first, or None).

    A here-doc is the shell's own syntax, so `RUN cat <<EOF > /f` has to reach
    the shell with the body after it: reading only the bodies ran them as the
    command and dropped the redirect. A lone `RUN <<EOF` is the one form whose
    body *is* the command, and a body opening with a shebang is a script for the
    interpreter it names rather than for the stage's shell, so it becomes a file
    to exec (the name carries random bytes because it lands in a tree the step
    itself can write).
    """
    if instr["exec_form"]:
        return list(instr["value"]), None

    heredocs = instr.get("heredocs") or []
    value = str(instr["value"])
    if not heredocs:
        return [*list(stage.shell), value], None

    if len(heredocs) == 1 and _BARE_HEREDOC_RE.match(value):
        body = heredocs[0]["body"]
        if body.startswith("#!"):
            name = f".chroot-distro-step-{os.urandom(4).hex()}"
            return ["/" + name], (name, body)
        return [*list(stage.shell), body], None

    rebuilt = value + "".join("\n" + hd["body"] + hd["tag"] for hd in heredocs)
    return [*list(stage.shell), rebuilt], None


def _write_step_script(stage: typing.Any, name: str, body: str) -> None:
    """Plant a here-doc script at the top of *stage*'s rootfs, executable.

    Written through the stage's own descriptor with O_EXCL, like every other
    write into a tree a step has had the run of, and 0755 explicitly because the
    mode the create asked for went through the umask.
    """
    try:
        rootfs_fd = _rootfs_fd(stage)
        try:
            fd, _st = dirfd.open_new_at(rootfs_fd, name, 0o755)
            try:
                os.write(fd, body.encode())
                os.fchmod(fd, 0o755)
            finally:
                os.close(fd)
        finally:
            os.close(rootfs_fd)
    except OSError as exc:
        raise BuildError(f"cannot write the RUN here-doc script into the stage rootfs: {exc}") from exc


def _remove_step_script(stage: typing.Any, name: str) -> None:
    """Take the planted script back out of the rootfs."""
    rootfs_fd = _rootfs_fd(stage)
    try:
        dirfd.unlink_quietly(rootfs_fd, name)
    finally:
        os.close(rootfs_fd)


def _run_extra_inputs(engine: typing.Any, stage: typing.Any, mounts: list[RunMount]) -> str:
    """Everything this step reads that its own instruction text does not carry.

    The platforms come first, and the base manifest with them: a stage built for
    another platform runs other binaries, and the chained parent digest does not
    always tell the two apart, since a `FROM scratch` stage has no parent layer
    at all and a single-platform base image hands the same layers to every
    platform asked for. Then how the step is executed, because a command
    emulated through binfmt_misc and the same command run native are not the
    same command, and the isolation mode decides which mounts it sees. Then every
    tree a `--mount` exposes, and last the env and ARG state the command reads.

    A secret is deliberately not here, in any form: its id travels in the
    instruction's own flags, which is what BuildKit keys on, and its value must
    never reach a cache key.
    """
    lines = [
        f"stage-platform={stage.platform.format()}",
        f"target-platform={engine.target_platform.format()}",
        f"build-platform={engine.build_platform.format()}",
        f"base-manifest={stage.base_manifest_digest}",
        f"exec={_exec_mode(engine, stage)}",
        f"isolation={engine.isolation_mode}",
        *mount_cache_inputs(engine, mounts),
    ]
    lines.extend(f"env {k}={v}" for k, v in sorted(engine.expansion_scope().items()))
    return "\n".join(lines)


def _exec_mode(engine: typing.Any, stage: typing.Any) -> str:
    """Whether this stage's binaries run on the CPU or through an emulator."""
    foreign = needs_emulation(stage.platform.to_arch(), engine.build_platform.to_arch())
    return "emulated" if foreign else "native"


def _require_emulator(engine: typing.Any, stage: typing.Any) -> None:
    """Refuse a foreign-arch step this host has no binfmt_misc handler for.

    `build`'s preflight reads the Dockerfile's own RUN lines, so it cannot see a
    step a base image's ONBUILD fired; that one arrives here instead. Asked at the
    exec itself rather than per stage, which is also what keeps a cached foreign
    step working on a host with no emulator: nothing execs for a cache hit.
    """
    arch = stage.platform.to_arch()
    if not needs_emulation(arch, engine.build_platform.to_arch()):
        return
    interpreter, reason = ensure_handler(arch)
    if interpreter is None:
        raise BuildError(
            f"cannot run a step for '{stage.platform}' on a '{engine.build_platform}' "
            f"host: no emulator was registered ({reason})."
        )


def _exec_chroot(
    engine: typing.Any,
    stage: typing.Any,
    command: list[str],
    stdin_input: str | None,
    mounts: list[RunMount] | None = None,
) -> int:
    """Run *command* chrooted into *stage*'s rootfs; return its exit code."""
    _require_emulator(engine, stage)
    rootfs = stage.rootfs_dir

    from chroot_distro.commands.login.chroot_cmd import build_chroot_config
    from chroot_distro.commands.login.passwd import find_user_groups

    uid, gid = resolve_user_for_chroot(rootfs, stage.user, root_fd=stage.rootfs_fd)

    user_name = stage.user or "root"
    user_spec = user_name if not user_name.isdigit() else str(uid)
    groups = find_user_groups(rootfs, user_spec, str(gid))

    config = build_chroot_config(
        rootfs=rootfs,
        login_uid=str(uid) if uid else None,
        login_gid=str(gid) if gid else None,
        groups=groups,
        workdir=stage.workdir or "/",
        inner_cmd=command,
    )

    child_env = _build_child_env(engine, stage)

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
        session = isolation.max_isolation_session if engine.isolation_mode == "max" else isolation.namespace_session
        with session(container_key, rootfs, minimal=True) as holder:
            if holder is not None:
                with run_mount_session(engine, stage, mounts or [], holder=holder) as extra_env:
                    return _run_in_holder(holder, config, {**child_env, **extra_env})
            return _run_plain(rootfs, config, child_env, stdin_input, engine, stage, mounts or [])

    return _run_plain(rootfs, config, child_env, stdin_input, engine, stage, mounts or [])


def _run_in_holder(holder: typing.Any, config: typing.Any, child_env: dict[str, str]) -> int:
    """Run the step inside the holder's namespaces; return its exit code.

    The rootfs is entered by path here, not through the stage's pinned
    descriptor: that descriptor names the tree as the host's mount namespace
    sees it, while the step has to see the one this holder's namespace holds,
    which is where its binds were applied.
    """
    pid = _fork_step(config, child_env, holder=holder)
    return _wait_for_child_with_signals(pid)


def _mount_point(rootfs: str, guest_path: str) -> str | None:
    """Make the directory *guest_path* names inside *rootfs*. Path, or None.

    A bind target is a name, and os.makedirs(exist_ok=True) accepts a symlink
    to a directory while mount(2) resolves the name all over again. Every
    component of one of these is image content and the step's binds are applied
    in the host's mount namespace, so an image shipping `dev -> <host dir>` had
    the host's own /dev mounted onto that directory, `dev/pts` created inside
    it, and the mount left behind afterwards: unmount_all() sweeps what is
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


def _step_stdin(stdin_input: str | None) -> int:
    """A readable descriptor for the step's stdin. The caller closes it.

    A file rather than a pipe when there is input: nothing has to keep writing
    while the step reads, so a body larger than the pipe buffer cannot deadlock
    the build.
    """
    if stdin_input is None:
        return os.open(os.devnull, os.O_RDONLY)
    fd = os.memfd_create("run-stdin", 0)
    os.write(fd, stdin_input.encode())
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def _fork_step(
    config: typing.Any,
    env: dict[str, str],
    *,
    stdin_input: str | None = None,
    holder: typing.Any = None,
    rootfs_fd: int | None = None,
) -> int:
    """Fork the step's command and return the child's pid.

    The child leads a session of its own, so the process group _stop_step
    sweeps afterwards is the step's and nothing else's. With *rootfs_fd* it
    chroots onto that pinned descriptor rather than onto the rootfs path, so
    the name the build validated is not resolved a second time; the chroot is
    the last thing it does before the exec, since it has to happen after the
    namespaces are joined.
    """
    stdin_fd = _step_stdin(stdin_input)
    try:
        pid = os.fork()
    except OSError:
        os.close(stdin_fd)
        raise

    if pid == 0:
        # --- Child ---
        try:
            os.setsid()
            os.dup2(stdin_fd, 0)
            if holder is not None:
                from chroot_distro.syscalls.nsenter import enter_namespaces

                enter_namespaces(holder.pid, holder._live_ns_flags())
            newroot = config.rootfs
            if rootfs_fd is not None:
                os.fchdir(rootfs_fd)
                newroot = os.curdir
            enter_chroot(
                newroot,
                uid=config.uid,
                gid=config.gid,
                groups=config.groups,
                workdir=config.workdir,
            )
            _try_exec(config.command, env)
        except BaseException:
            os._exit(127)

    os.close(stdin_fd)
    return pid


def _run_plain(
    rootfs: str,
    config: typing.Any,
    child_env: dict[str, str],
    stdin_input: str | None,
    engine: typing.Any = None,
    stage: typing.Any = None,
    mounts: list[RunMount] | None = None,
) -> int:
    """Run the step with host-namespace bind mounts (no isolation)."""
    import chroot_distro.helpers.mount_manager as mount_manager
    from chroot_distro.commands.login import bindings

    resolved_binds, _ = bindings.get_bindings(rootfs=rootfs, minimal=True)

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
            # Before anything is spawned, so a descendant that outlives its own
            # parent is reparented here rather than onto init.
            _become_subreaper()
            baseline = set(_adopted())
            try:
                pid = _fork_step(
                    config,
                    {**child_env, **extra_env},
                    stdin_input=stdin_input,
                    rootfs_fd=stage.rootfs_fd if stage is not None else None,
                )
            except OSError as exc:
                raise BuildError(f"could not start the RUN step: {exc}") from exc
            try:
                returncode = _wait_for_child(pid)
            except KeyboardInterrupt:
                with contextlib.suppress(OSError):
                    os.killpg(pid, signal.SIGTERM)
                _wait_for_child(pid)
                _stop_step(pid, baseline, quiet=True)
                raise
            _stop_step(pid, baseline, quiet=engine is not None and engine.quiet)
            return returncode
    finally:
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
    command outlives the shell that started it, and a daemon goes further
    (fork, setsid, fork, which leaves the step's process group as well). Either
    way the process is then no relation of ours that any interface will name.
    As a subreaper it is reparented here instead of onto init, so
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
    nothing, since the previous step is stopped before the next one begins, but
    a straggler that would not die must not be counted against every step that
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
    that group goes too, otherwise its children outlive it by a generation.
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


def _refuse_host_exec(engine: typing.Any, key: str) -> bool:
    """True when *key* aims a loader, so the Dockerfile may not set it for a step.

    constants.is_host_exec_var states the rule as one about provenance, and
    that is what this applies. Both of the sources filtered here are the
    Dockerfile's, `stage.env` (its ENV lines, and a base image's, seeded at
    FROM) and the ARG values keyed by names it declared, while the host
    variables read below come from os.environ, which is the user's own
    environment and stays sovereign.

    The value still goes into the image config: what the Dockerfile says about
    the image it produces is its author's business, and only the command this
    build execs is refused it.
    """
    if not is_host_exec_var(key):
        return False
    if key not in engine.warned_host_exec:
        engine.warned_host_exec.add(key)
        warn(
            f"ignoring '{key}' for RUN steps: it aims the dynamic loader rather than the "
            f"command, and this build did not set it. It stays in the image config."
        )
    return True


def _build_child_env(engine: typing.Any, stage: typing.Any) -> dict[str, str]:
    env = {}
    env["PATH"] = stage.env.get("PATH") or DEFAULT_PATH_ENV
    env["HOME"] = stage.env.get("HOME", "/root")
    env["TERM"] = os.environ.get("TERM", "") or "xterm-256color"
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm

    # A predefined ARG (proxies and the like) reaches the step from the host
    # environment whether the Dockerfile declared it or not.
    for k in PREDEFINED_ARGS:
        v = os.environ.get(k, "")
        if v:
            env[k] = v

    for k in stage.declared_args:
        if k in stage.args and not _refuse_host_exec(engine, k):
            env[k] = stage.args[k]

    for k, v in stage.env.items():
        if _refuse_host_exec(engine, k):
            continue
        env[k] = v

    return env
