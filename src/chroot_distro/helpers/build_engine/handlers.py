import contextlib
import json
import logging
import os
import typing

from chroot_distro import dirfd
from chroot_distro.atomic import publish_file
from chroot_distro.helpers.build_engine.constants import PREDEFINED_ARGS
from chroot_distro.helpers.build_engine.copy_step import do_add, do_copy
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.parsing import (
    parse_kv_list,
    split_arg,
    split_operands,
    to_argv,
)
from chroot_distro.helpers.build_engine.run_step import do_run
from chroot_distro.helpers.build_engine.users import resolve_user_for_chroot
from chroot_distro.helpers.docker import layer_cache_path
from chroot_distro.helpers.layer_diff import write_files_layer
from chroot_distro.helpers.tar_extract import _safe_resolve

log = logging.getLogger(__name__)


def do_arg(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ARG NAME[=DEFAULT]: declare a build-time variable for this stage.

    Resolution order: --build-arg from the CLI, then the Dockerfile
    default, then the global-ARG value re-exposed by a bare `ARG NAME`,
    then a host env var when NAME is one of the predefined ARGs.
    Falls back to the empty string.
    """
    key, default = split_arg(instr["value"])
    if not key:
        raise BuildError(f"Invalid ARG at line {instr['lineno']}: {instr['value']!r}")
    stage = engine.current
    stage.declared_args.add(key)
    if key in engine.user_build_args:
        stage.args[key] = engine.user_build_args[key]
    elif default is not None:
        stage.args[key] = default
    elif key in engine.global_args and key in engine.declared_global:
        # Bare `ARG NAME` re-exposes the global value inside the stage.
        stage.args[key] = engine.global_args[key]
    elif key in PREDEFINED_ARGS:
        stage.args[key] = os.environ.get(key, "")
    else:
        stage.args[key] = ""


def do_env(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ENV KEY=VALUE [KEY=VALUE...]: persist env vars in the image config.

    Mirrors the value into the stage's live ENV scope so subsequent
    instructions (including RUN) can expand `${KEY}` references.
    """
    value = instr["value"]
    if instr["exec_form"]:
        # ENV does not have an exec form in the spec; treat the
        # parsed list as space-joined raw value.
        value = " ".join(value)
    pairs = parse_kv_list(value)
    cfg = engine.current.image_config.setdefault("config", {})
    env_list = cfg.get("Env") or []
    env_map = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in env_list if isinstance(e, str) and "=" in e}
    for k, v in pairs:
        env_map[k] = v
        engine.current.env[k] = v
    cfg["Env"] = [f"{k}={v}" for k, v in env_map.items()]


def do_label(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """LABEL k=v [k=v...]: add OCI-style annotation labels."""
    value = instr["value"]
    if instr["exec_form"]:
        value = " ".join(value)
    pairs = parse_kv_list(value)
    cfg = engine.current.image_config.setdefault("config", {})
    labels = dict(cfg.get("Labels") or {})
    for k, v in pairs:
        labels[k] = v
    cfg["Labels"] = labels


def do_maintainer(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """MAINTAINER "Name <addr>": legacy form of LABEL maintainer=."""
    cfg = engine.current.image_config.setdefault("config", {})
    labels = dict(cfg.get("Labels") or {})
    labels["maintainer"] = str(instr["value"]).strip()
    cfg["Labels"] = labels


def do_user(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """USER name[:group]: set the identity that future RUN steps use."""
    engine.current.user = str(instr["value"]).strip()
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["User"] = engine.current.user


def _stamp_build_dir(rootfs: str, parts: list[str], uid: int, gid: int) -> None:
    """Own and lock down one directory WORKDIR created, through a descriptor.

    A named chown or chmod acts on whatever the name leads to, and these are
    host-side writes with nothing confining them: a symlink standing where the
    directory should be would hand its target away instead. Linux has no
    AT_SYMLINK_NOFOLLOW for fchmodat(2) either, so the descriptor is the only
    way to name the inode the walk validated.
    """
    fd = dirfd.opendir_under(rootfs, parts)
    if fd is None:
        return
    try:
        with contextlib.suppress(OSError):
            os.fchown(fd, uid, gid)
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def do_workdir(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """WORKDIR PATH: set the cwd and create the directory on disk.

    Emits a thin layer covering any newly-created ancestor directories
    so the path still exists when the image is later applied to a
    fresh rootfs by `install`.
    """
    path = str(instr["value"]).strip()
    if not path:
        raise BuildError(f"WORKDIR with empty path at line {instr['lineno']}.")
    # Normalised whether or not it is absolute. Only the relative branch used to
    # be, so `WORKDIR /../../../x` carried its ".." into the host path below --
    # and os.makedirs() then created that directory as many levels above the
    # rootfs as the instruction asked for, anywhere the invoking user can write,
    # with a chmod behind it; the layer picked up a matching "../x" arcname.
    # ".." is resolved against the guest's "/" here, clamping at the image root
    # the way a chroot does and the way Docker reads it.
    path = os.path.normpath(os.path.join("/", engine.current.workdir or "/", path))
    engine.current.workdir = path
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["WorkingDir"] = path

    # Create the directory inside the rootfs and emit a thin layer that
    # captures every newly-created ancestor, so the path also exists when the
    # image is applied to a fresh rootfs by `install`.
    #
    # The path is resolved before anything is created and then created off a
    # descriptor per level. os.makedirs(), os.chown() and os.chmod() address
    # every level by name, so an image shipping `/x -> /tmp/victim` had
    # `WORKDIR /x/sub` create -- and then hand over -- a directory on the
    # *host*, outside the rootfs entirely; a base image's `ONBUILD WORKDIR`
    # reaches that without the Dockerfile carrying the line at all. Refusing
    # symlinked components is not an option, since `/var/run -> /run` ships in
    # nearly every distro image: _safe_resolve follows each link but re-anchors
    # an absolute target at the rootfs the way the guest's own view does, and
    # makedirs_under then refuses a component planted after the resolve rather
    # than following it. The arcnames name the resolved location, which is
    # where the directories really landed.
    rootfs = engine.current.rootfs_dir
    resolved = _safe_resolve(rootfs, path.strip("/").split("/"))
    if resolved is None:
        return
    rel = os.path.relpath(resolved, rootfs)
    parts = [] if rel == os.curdir else rel.split(os.sep)

    new_dirs = [parts[:depth] for depth in range(1, len(parts) + 1) if not os.path.lexists(os.path.join(rootfs, *parts[:depth]))]

    uid, gid = resolve_user_for_chroot(rootfs, engine.current.user)
    if dirfd.makedirs_under(rootfs, parts) is None:
        return
    _stamp_build_dir(rootfs, parts, uid, gid)

    if not new_dirs:
        return

    file_map = {}
    for prefix in new_dirs:
        _stamp_build_dir(rootfs, prefix, uid, gid)
        file_map["/".join(prefix)] = {
            "kind": "dir",
            "mode": 0o700,
            "uid": uid,
            "gid": gid,
            "mtime": 0,
        }

    tmp_layer_path = os.path.join(
        engine.tmp_root,
        f"layer-{engine.current.index}-{len(engine.current.layers)}.tar.gz",
    )
    digest, size, diff_id = write_files_layer(file_map, tmp_layer_path)
    # See run_step: the layer cache is walked down to, not named.
    publish_file(tmp_layer_path, layer_cache_path(digest))
    engine.current.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
    engine.current.parent_layer_digest = digest


def do_cmd(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """CMD [argv]/CMD command: default argv for `chroot-distro run`."""
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["Cmd"] = to_argv(instr, engine.current.shell)


def do_entrypoint(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ENTRYPOINT [argv]: fixed argv that CMD/run-args are appended to."""
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["Entrypoint"] = to_argv(instr, engine.current.shell)
    # Docker semantics: setting ENTRYPOINT resets CMD (typically
    # inherited from the base image). Users who want both put CMD
    # *after* ENTRYPOINT in the Dockerfile, which our linear
    # interpreter already handles correctly.
    cfg["Cmd"] = None


def do_expose(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """EXPOSE port[/proto]: record container ports in image config."""
    cfg = engine.current.image_config.setdefault("config", {})
    ports = dict(cfg.get("ExposedPorts") or {})
    for tok in split_operands(instr["value"], instr):
        token = tok if "/" in tok else tok + "/tcp"
        ports[token] = {}
    cfg["ExposedPorts"] = ports


def do_volume(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """VOLUME PATH [PATH...]: record volume mount points in image config."""
    cfg = engine.current.image_config.setdefault("config", {})
    vols = dict(cfg.get("Volumes") or {})
    paths = list(instr["value"]) if instr["exec_form"] else split_operands(instr["value"], instr)
    for p in paths:
        vols[p] = {}
    cfg["Volumes"] = vols


def do_stopsignal(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """STOPSIGNAL signal: signal sent to stop the container (metadata only)."""
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["StopSignal"] = str(instr["value"]).strip()


def do_shell(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """SHELL ["/path", "-flag"]: argv used as the prefix for shell-form RUN."""
    if not instr["exec_form"]:
        raise BuildError(f"SHELL must be in JSON exec form at line {instr['lineno']}.")
    engine.current.shell = list(instr["value"])
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["Shell"] = list(instr["value"])


def do_healthcheck(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """HEALTHCHECK [NONE|CMD ...]: record healthcheck cmd in image config.

    Accepted forms are HEALTHCHECK NONE (clears any inherited check)
    or HEALTHCHECK [opts] CMD ... — opts like --interval are parsed
    but not enforced under chroot-distro.
    """
    value = str(instr["value"]).strip()
    cfg = engine.current.image_config.setdefault("config", {})
    upper = value.split(None, 1)[0].upper() if value else ""
    if upper == "NONE":
        cfg["Healthcheck"] = {"Test": ["NONE"]}
        return
    # We parse the inner CMD only; HEALTHCHECK flags like --interval
    # are accepted but not enforced under chroot-distro.
    if not upper.startswith("CMD"):
        raise BuildError(f"HEALTHCHECK must be 'NONE' or 'CMD ...' at line {instr['lineno']}.")
    rest = value[len("CMD") :].strip()
    argv = None
    try:
        parsed = json.loads(rest)
        if isinstance(parsed, list):
            argv = ["CMD", *list(parsed)]
    except (json.JSONDecodeError, ValueError) as exc:
        log.debug("HEALTHCHECK not JSON-formatted, fallback to CMD-SHELL: %s", exc)
    if argv is None:
        argv = ["CMD-SHELL", rest]
    cfg["Healthcheck"] = {"Test": argv}


def do_onbuild(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ONBUILD <instr>: queue an instruction to run when this image is FROM-ed."""
    inner = instr["value"]
    if not isinstance(inner, dict):
        raise BuildError(f"ONBUILD is malformed at line {instr['lineno']}.")
    if engine.current is None:
        raise BuildError(f"ONBUILD before FROM at line {instr['lineno']}.")
    cfg = engine.current.image_config.setdefault("config", {})
    triggers = list(cfg.get("OnBuild") or [])
    triggers.append(inner["raw"])
    cfg["OnBuild"] = triggers


HANDLERS = {
    "ADD": do_add,
    "ARG": do_arg,
    "CMD": do_cmd,
    "COPY": do_copy,
    "ENTRYPOINT": do_entrypoint,
    "ENV": do_env,
    "EXPOSE": do_expose,
    "HEALTHCHECK": do_healthcheck,
    "LABEL": do_label,
    "MAINTAINER": do_maintainer,
    "RUN": do_run,
    "SHELL": do_shell,
    "STOPSIGNAL": do_stopsignal,
    "USER": do_user,
    "VOLUME": do_volume,
    "WORKDIR": do_workdir,
}
