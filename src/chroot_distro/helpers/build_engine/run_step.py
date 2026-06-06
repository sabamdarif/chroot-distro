import contextlib
import os
import signal
import subprocess
import typing

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
from chroot_distro.helpers.build_engine.users import resolve_user_for_chroot
from chroot_distro.helpers.docker import apply_layer, layer_cache_path
from chroot_distro.helpers.layer_diff import (
    diff_snapshots,
    snapshot,
    write_layer_tar,
)
from chroot_distro.message import log_info


def do_run(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """RUN <cmd>: execute command under chroot and snapshot the diff into a layer.

    Cache lookup happens first: a recipe-hash hit applies the cached
    layer and skips chroot entirely. On a miss, snapshot the rootfs,
    exec under chroot, snapshot again, pack the delta into a gzipped
    OCI layer, and record the (recipe-hash → layer) entry.
    """
    stage = engine.current

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
    exit_code = _exec_chroot(engine, stage, command, stdin_input)
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
    final_path = layer_cache_path(digest)
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    os.replace(tmp_layer_path, final_path)

    stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
    stage.parent_layer_digest = digest
    cache_record(recipe, digest, diff_id, size, {})


def _run_extra_inputs(engine: typing.Any) -> str:
    """Encode env + ARG state visible to RUN for the recipe hash."""
    scope = engine.expansion_scope()
    items = sorted(scope.items())
    return "\n".join(f"{k}={v}" for k, v in items)


def _exec_chroot(engine: typing.Any, stage: typing.Any, command: list[str], stdin_input: str | None) -> int:
    """Invoke chroot against *stage*'s rootfs to execute *command*."""
    rootfs = stage.rootfs_dir

    import chroot_distro.helpers.mount_manager as mount_manager
    from chroot_distro.commands.login import bindings
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

    resolved_binds, _ = bindings.get_bindings(rootfs=rootfs, minimal=True)

    # Pre-clean stale mounts if any
    with contextlib.suppress(Exception):
        mount_manager.unmount_all(rootfs)

    try:
        for src, dst in resolved_binds:
            is_run = (os.path.realpath(dst) == os.path.realpath(os.path.join(rootfs, "run")))
            mount_manager.safe_mount(src, dst, recursive=is_run)

        stdin_arg = subprocess.PIPE if stdin_input is not None else subprocess.DEVNULL
        proc = subprocess.Popen(
            chroot_args,
            env=child_env,
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
            raise
        return proc.returncode
    except FileNotFoundError as exc:
        raise BuildError(f"chroot command execution failed: {exc}") from exc
    finally:
        # Clean up mounts
        mount_manager.unmount_all(rootfs)


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
