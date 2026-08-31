# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The metadata instructions: everything that edits the image config.

One `do_*` per instruction, dispatched through `HANDLERS`, each taking the engine
and one parsed instruction record and mutating `engine.current`. ADD, COPY and
RUN are the exceptions and live in their own modules, imported here only so the
table is complete.

Two handlers do more than write a dict. `do_workdir` creates the directory and
emits a thin layer covering the ancestors it made, because the path has to exist
when `install` later applies the image to a fresh rootfs; it resolves the guest
path first and then creates and stamps each level off a descriptor, since an
image shipping `/x -> /tmp/victim` would otherwise have `WORKDIR /x/sub` create
and chown a directory on the *host*, and a base image's `ONBUILD WORKDIR`
reaches that without the Dockerfile carrying the line at all. `do_env` drops an
`LD_*` name when the ENV line came from a base image's ONBUILD trigger, and
drops it from the built config too, so a container run from the image does not
inherit it either.

`do_entrypoint` clearing Cmd is Docker's rule and not an oversight: a Dockerfile
wanting both puts CMD after ENTRYPOINT.
"""

import contextlib
import json
import os
import typing

from chroot_distro import dirfd
from chroot_distro.atomic import publish_file
from chroot_distro.helpers.build_engine.constants import PREDEFINED_ARGS, is_host_exec_var
from chroot_distro.helpers.build_engine.copy_step import do_add, do_copy
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.parsing import (
    parse_duration_ns,
    parse_kv_list,
    split_args,
    split_operands,
    to_argv,
)
from chroot_distro.helpers.build_engine.run_step import do_run
from chroot_distro.helpers.build_engine.users import resolve_user_for_chroot
from chroot_distro.helpers.docker import layer_cache_path
from chroot_distro.helpers.layer_diff import write_files_layer
from chroot_distro.helpers.tar_extract import safe_resolve_parts
from chroot_distro.message import warn


def do_arg(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ARG NAME[=DEFAULT] [NAME[=DEFAULT]...]: declare build-time variables.

    Resolution order per name: --build-arg from the CLI, then the Dockerfile
    default, then the global-ARG value re-exposed by a bare `ARG NAME`,
    then the automatic platform value for a TARGET*/BUILD* name, then a
    host env var when NAME is one of the predefined ARGs. Falls back to
    the empty string.
    """
    names = [(key, default) for key, default in split_args(instr["value"]) if key]
    if not names:
        raise BuildError(f"Invalid ARG at line {instr['lineno']}: {instr['value']!r}")
    stage = engine.current
    platform_args = engine.platform_args()
    for key, default in names:
        stage.declared_args.add(key)
        if key in engine.user_build_args:
            stage.args[key] = engine.user_build_args[key]
        elif default is not None:
            stage.args[key] = default
        elif key in engine.global_args and key in engine.declared_global:
            # Bare `ARG NAME` re-exposes the global value inside the stage.
            stage.args[key] = engine.global_args[key]
        elif key in platform_args:
            # The automatic platform values are global as well, so a bare
            # `ARG TARGETARCH` is what brings one into the stage.
            stage.args[key] = platform_args[key]
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
        # ENV has no exec form in the spec, so a parsed list is joined back up.
        value = " ".join(value)
    pairs = parse_kv_list(value)
    cfg = engine.current.image_config.setdefault("config", {})
    env_list = cfg.get("Env") or []
    env_map = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in env_list if isinstance(e, str) and "=" in e}
    # An ENV fired by the base image's ONBUILD is the image's line and not the
    # author's, so it is held to the rule the image's own Env is held to: the
    # LD_* namespace aims the dynamic loader rather than the command that
    # carries it (see constants.is_host_exec_var). Dropped rather than merely
    # not applied, so the built image does not carry it on to whoever runs a
    # container from it either.
    from_image = engine.firing_onbuild
    for k, v in pairs:
        if from_image and is_host_exec_var(k):
            warn(
                f"ignoring ONBUILD ENV '{k}' from the base image: it aims the dynamic "
                f"loader rather than the command that carries it."
            )
            continue
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


def _build_dir_fd(
    rootfs: str,
    parts: typing.Sequence[str],
    rootfs_fd: int | None,
    *,
    create: bool = False,
) -> int | None:
    """A descriptor on the directory *parts* names under the rootfs, or None.

    Descends from the rootfs descriptor when the caller has pinned one, so the
    levels above the directory are not resolved by name a second time; only a
    caller without a pin (a test working on a tree it made itself) opens the
    rootfs by name.
    """
    if rootfs_fd is None:
        return dirfd.opendir_under(rootfs, parts, create=create)
    try:
        return dirfd.descend_at(rootfs_fd, parts, create=create)
    except OSError:
        return None


def _stamp_build_dir(
    rootfs: str,
    parts: typing.Sequence[str],
    uid: int,
    gid: int,
    rootfs_fd: int | None = None,
    *,
    create: bool = False,
) -> bool:
    """Own and lock down one directory WORKDIR created, through a descriptor.

    A named chown or chmod acts on whatever the name leads to, and these are
    host-side writes with nothing confining them: a symlink standing where the
    directory should be would hand its target away instead. Linux has no
    AT_SYMLINK_NOFOLLOW for fchmodat(2) either, so the descriptor is the only
    way to name the inode the walk validated.

    With create=True the missing levels are made on the way down, so the
    directory is created and stamped in one walk rather than made by name and
    then reopened. False means it is not reachable inside the rootfs.
    """
    fd = _build_dir_fd(rootfs, parts, rootfs_fd, create=create)
    if fd is None:
        return False
    try:
        with contextlib.suppress(OSError):
            os.fchown(fd, uid, gid)
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return True


def _missing_levels(rootfs: str, parts: typing.Sequence[str], rootfs_fd: int | None = None) -> list[list[str]]:
    """The prefixes of *parts* that do not exist yet, shallowest first.

    One descent answers for every level, each looked up off the descriptor of
    the level above; asking os.path.lexists() per prefix resolved every
    component above it again, once per level, and each of those resolves was a
    fresh chance for a component to have changed underneath.

    Everything below the first gap is missing too, so the walk stops
    descending there.
    """
    try:
        fd = dirfd.reopen(rootfs_fd) if rootfs_fd is not None else dirfd.opendir(rootfs)
    except OSError:
        return [list(parts[:depth]) for depth in range(1, len(parts) + 1)]

    missing: list[list[str]] = []
    try:
        for depth, comp in enumerate(parts, start=1):
            if missing or not dirfd.exists_at(fd, comp):
                missing.append(list(parts[:depth]))
                continue
            try:
                nxt = dirfd.opendir_at(fd, comp)
            except OSError:
                break
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)
    return missing


def do_workdir(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """WORKDIR PATH: set the cwd and create the directory on disk.

    Emits a thin layer covering any newly-created ancestor directories
    so the path still exists when the image is later applied to a
    fresh rootfs by `install`.
    """
    path = str(instr["value"]).strip()
    if not path:
        raise BuildError(f"WORKDIR with empty path at line {instr['lineno']}.")
    # Normalised whether the path is absolute or not: an unnormalised
    # `WORKDIR /../../../x` would carry its ".." into the host path below and
    # create, and chmod, a directory that many levels above the rootfs. ".." is
    # resolved against the guest's "/", clamping at the image root the way a
    # chroot does and the way Docker reads it.
    path = os.path.normpath(os.path.join("/", engine.current.workdir or "/", path))
    engine.current.workdir = path
    cfg = engine.current.image_config.setdefault("config", {})
    cfg["WorkingDir"] = path

    # The path is resolved before anything is created, then created off a
    # descriptor per level. Naming every level instead, the way os.makedirs()
    # and os.chown() do, lets an image shipping `/x -> /tmp/victim` have
    # `WORKDIR /x/sub` create and hand over a directory on the *host*, and a
    # base image's `ONBUILD WORKDIR` reaches that without the Dockerfile
    # carrying the line at all. Refusing symlinked components is not an option,
    # since `/var/run -> /run` ships in nearly every distro image: safe_resolve
    # follows each link but re-anchors an absolute target at the rootfs the way
    # the guest's own view does, and makedirs_under refuses a component planted
    # after the resolve rather than following it. The arcnames name the resolved
    # location, which is where the directories really landed.
    rootfs = engine.current.rootfs_dir
    rootfs_fd = engine.current.rootfs_fd
    parts = safe_resolve_parts(rootfs, path.strip("/").split("/"), root_fd=rootfs_fd)
    if parts is None:
        return

    new_dirs = _missing_levels(rootfs, parts, rootfs_fd)

    uid, gid = resolve_user_for_chroot(rootfs, engine.current.user, root_fd=rootfs_fd)
    if not _stamp_build_dir(rootfs, parts, uid, gid, rootfs_fd, create=True):
        return

    if not new_dirs:
        return

    file_map = {}
    for prefix in new_dirs:
        _stamp_build_dir(rootfs, prefix, uid, gid, rootfs_fd)
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
    # Docker semantics: setting ENTRYPOINT resets the CMD inherited from the
    # base image, so a Dockerfile wanting both puts CMD after ENTRYPOINT.
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


# A HEALTHCHECK option to the image-config field it is stored in. Every one is a
# duration; --retries is the odd one out and is handled on its own.
_HEALTHCHECK_INTERVALS = {
    "interval": "Interval",
    "timeout": "Timeout",
    "start-period": "StartPeriod",
    "start-interval": "StartInterval",
}

# What a duration below this means to Docker: nothing a check can be run at.
_MIN_HEALTHCHECK_NS = 1_000_000


def _healthcheck_test(rest: str, lineno: int) -> list[str]:
    """The Test array for a `HEALTHCHECK CMD`: exec form as argv, shell form via a shell.

    A JSON array of strings is the command itself; anything else is text for a
    shell, including a JSON array holding something that is not a string, which
    must not reach the config as one.
    """
    if not rest:
        raise BuildError(f"HEALTHCHECK CMD needs a command at line {lineno}.")
    with contextlib.suppress(json.JSONDecodeError, ValueError):
        parsed = json.loads(rest)
        if isinstance(parsed, list) and parsed and all(isinstance(x, str) for x in parsed):
            return ["CMD", *parsed]
    return ["CMD-SHELL", rest]


def _healthcheck_retries(value: str, lineno: int) -> int:
    if not value.isdigit():
        raise BuildError(f"HEALTHCHECK --retries '{value}' is not a count (line {lineno}).")
    return int(value)


def do_healthcheck(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """HEALTHCHECK [OPTIONS] CMD ... | HEALTHCHECK NONE: record the check.

    The options are recorded, not enforced: nothing here runs a check, but the
    image this build publishes tells a runtime that does how to run one, and
    dropping them would publish an image the Dockerfile does not describe. A
    duration is stored as whole nanoseconds, and a zero is left out, which is how
    the config spells "inherit".
    """
    value = str(instr["value"]).strip()
    flags = instr.get("flags") or {}
    lineno = instr["lineno"]
    cfg = engine.current.image_config.setdefault("config", {})
    head, _, rest = value.partition(" ")
    upper = head.upper()

    for flag in flags:
        if flag not in _HEALTHCHECK_INTERVALS and flag != "retries":
            raise BuildError(f"HEALTHCHECK --{flag} is not supported (line {lineno}); refusing to silently ignore it.")

    if upper == "NONE":
        if rest.strip() or flags:
            raise BuildError(f"HEALTHCHECK NONE takes no arguments or options (line {lineno}).")
        cfg["Healthcheck"] = {"Test": ["NONE"]}
        return
    if upper != "CMD":
        raise BuildError(f"HEALTHCHECK must be 'NONE' or 'CMD ...' at line {lineno}.")

    check: dict[str, typing.Any] = {"Test": _healthcheck_test(rest.strip(), lineno)}
    for flag, field in _HEALTHCHECK_INTERVALS.items():
        if flag not in flags:
            continue
        nanoseconds = parse_duration_ns(f"HEALTHCHECK --{flag}", str(flags[flag]), lineno)
        if not nanoseconds:
            continue
        if nanoseconds < _MIN_HEALTHCHECK_NS:
            raise BuildError(f"HEALTHCHECK --{flag} cannot be less than 1ms (line {lineno}).")
        check[field] = nanoseconds
    if "retries" in flags:
        retries = _healthcheck_retries(str(flags["retries"]), lineno)
        if retries:
            check["Retries"] = retries
    cfg["Healthcheck"] = check


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
