# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro build`: validate the request, run the engine, publish the result.

Everything the command can refuse is refused before anything is created or
fetched: an unreadable or unparsable Dockerfile, an unknown `--override-arch`, an
`--install-as` name already in use, a malformed tag, an output file that already
exists. A build that was going to be rejected therefore leaves behind no scratch
tree, no cache entry and no half-written archive.

One exclusive `BuildLock` per tag is held for the whole build, taken in lock-path
order so two concurrent builds with overlapping but differently spelled tag sets
cannot deadlock each other.

A `BuildError` or an `OSError` out of the engine is a build failure and ends as
one quoted line rather than a traceback: the engine's walks report a per-entry
failure and carry on, so an OSError that reaches here is a walk losing its
footing, not a bug. Anything else is left to `cli.main`.

`_make_build_tmp` is where this file's care goes and its own docstring says why.
It returns the scratch root's path plus descriptors on the root and on the
directory holding it; the stage rootfs trees, the ADD spool and every
`COPY --from` tree are made off the root descriptor, and the teardown removes the
root under the parent descriptor rather than resolving `build-tmp` again.

RUN steps have no isolation flag here: the mode comes from `CD_USE_ISOLATION` or
`CD_USE_NS` alone.
"""

import contextlib
import os
import re
import sys
import typing
from contextlib import ExitStack
from types import SimpleNamespace

from chroot_distro import dirfd
from chroot_distro.arch import get_device_cpu_arch, normalize_arch
from chroot_distro.commands.install import command_install
from chroot_distro.constants import (
    PROGRAM_NAME,
    RUNTIME_DIR,
)
from chroot_distro.helpers import namespace
from chroot_distro.helpers.build_engine import (
    BuildEngine,
    BuildError,
)
from chroot_distro.helpers.build_engine.events import make_reporter
from chroot_distro.helpers.docker import ARCH_TO_DOCKER
from chroot_distro.helpers.dockerfile import (
    DockerfileSyntaxError,
    parse_dockerfile,
)
from chroot_distro.helpers.isolation import use_isolation_env_enabled
from chroot_distro.helpers.oci_writer import (
    build_manifest_and_config,
    store_in_cache,
    write_oci_archive,
)
from chroot_distro.locking import BuildLock
from chroot_distro.message import C, crit_error, log_error, log_info, msg, quote_path, warn
from chroot_distro.names import is_valid_name, require_valid_name
from chroot_distro.paths import container_is_installed
from chroot_distro.progress import fmt_size


def command_build(args: typing.Any) -> None:
    """Implements `chroot-distro build`."""

    build_path = getattr(args, "path", None) or "."
    dockerfile_path = getattr(args, "dockerfile", None)
    tags = list(getattr(args, "tags", []) or [])
    build_args = _parse_build_args(getattr(args, "build_args", None) or [])
    override_arch = getattr(args, "override_arch", None) or ""
    target_stage = getattr(args, "target_stage", None) or None
    emulator = getattr(args, "emulator", None) or ""
    outputs = list(getattr(args, "outputs", []) or [])
    install_as = getattr(args, "install_as", None)

    if dockerfile_path is not None and not dockerfile_path:
        crit_error("Dockerfile path cannot be empty.")
        sys.exit(1)

    for out_file in outputs:
        if not out_file:
            crit_error("output file path cannot be empty.")
            sys.exit(1)

    if install_as is not None and not install_as:
        crit_error("--install-as value cannot be empty.")
        sys.exit(1)

    install_as = install_as or ""
    no_cache = bool(getattr(args, "no_cache", False))
    verbose = bool(getattr(args, "verbose", False))
    quiet = bool(getattr(args, "quiet", False))

    build_dir = os.path.abspath(os.path.expanduser(build_path))
    if dockerfile_path is None:
        dockerfile = os.path.join(build_dir, "Dockerfile")
    elif dockerfile_path == "-":
        dockerfile = "-"
    else:
        dockerfile = os.path.abspath(os.path.expanduser(dockerfile_path))

    if not os.path.isdir(build_dir):
        crit_error(f"build context '{build_dir}' is not a directory.")
        sys.exit(1)

    if dockerfile != "-" and not os.path.isfile(dockerfile):
        crit_error(f"required file '{dockerfile}' does not exist.")
        sys.exit(1)

    try:
        if dockerfile == "-":
            text = sys.stdin.read()
        else:
            with open(dockerfile, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
    except OSError as exc:
        crit_error(f"cannot read Dockerfile: {exc}")
        sys.exit(1)

    try:
        _directives, instructions = parse_dockerfile(text)
    except DockerfileSyntaxError as exc:
        crit_error(f"syntax error in Dockerfile: {exc}")
        sys.exit(1)

    if not instructions:
        crit_error("no instructions in Dockerfile.")
        sys.exit(1)

    if override_arch:
        target_arch = normalize_arch(override_arch)
        if target_arch is None:
            crit_error(f"unknown architecture '{override_arch}'.")
            sys.exit(1)
    else:
        target_arch = get_device_cpu_arch()

    if install_as:
        require_valid_name(install_as, kind="--install-as value")

        if container_is_installed(install_as):
            crit_error(
                f"container '{install_as}' defined by --install-as already "
                f"exists. Use '{PROGRAM_NAME} remove {install_as}' first or "
                f"'{PROGRAM_NAME} reset {install_as}' to rebuild."
            )
            sys.exit(1)

    if not tags:
        derived = _derive_tag_from_path(build_dir, dockerfile)
        if not derived:
            crit_error("cannot derive a tag from the build path. Pass '--tag' explicitly (e.g. --tag myapp:latest).")
            sys.exit(1)
        tags = [derived]

    for t in tags:
        if not _is_valid_tag(t):
            crit_error(
                f"tag '{t}' is not valid. A tag must start with an "
                f"alphanumeric character and contain only letters, "
                f"digits, underscores, dots, hyphens, slashes, or a "
                f"single colon for the version."
            )
            sys.exit(1)

    tags = [_with_explicit_tag(t) for t in tags]
    primary_tag = tags[0]

    for out_file in outputs:
        out_abs = os.path.abspath(os.path.expanduser(out_file))
        if os.path.exists(out_abs):
            crit_error(f"file '{out_abs}' already exists. Please specify a different name.")
            sys.exit(1)

    # Acquire one exclusive BuildLock per tag for the duration of the
    # build. Sorted by lock path so two concurrent builds with
    # overlapping but differently-ordered tag sets can't deadlock.
    build_locks = sorted(
        [BuildLock(t, target_arch, command="build") for t in tags],
        key=lambda lock: lock.lock_path,
    )

    with ExitStack() as lock_stack:
        for lock in build_locks:
            lock_stack.enter_context(lock)

        tmp_root, tmp_parent_fd, tmp_root_fd = _make_build_tmp()

        engine: BuildEngine | None = None
        try:
            secrets = _parse_secret_opts(getattr(args, "secrets", None) or [], tmp_root)
            ssh_sockets = _parse_ssh_opts(getattr(args, "ssh", None) or [])

            # build has no isolation CLI flag; both modes are env-var opt-in.
            isolation_mode = _resolve_build_isolation_mode()

            engine = BuildEngine(
                build_dir=build_dir,
                tmp_root=tmp_root,
                target_arch_pd=target_arch,
                user_build_args=build_args,
                target_stage=target_stage,
                verbose=verbose,
                quiet=quiet,
                no_cache=no_cache,
                emulator=emulator,
                isolation_mode=isolation_mode,
                secrets=secrets,
                ssh_sockets=ssh_sockets,
                reporter=make_reporter(getattr(args, "progress", "auto") or "auto", quiet),
                tmp_root_fd=tmp_root_fd,
            )

            try:
                final_stage = engine.run(instructions)
            except BuildError as exc:
                # A BuildError builds its message by interpolation and the
                # names it reports on are not the author's: a member of an
                # ADD'd archive (copy_step._materialise_files), an entry of a
                # base image, the output of a RUN step's own tooling.
                log_error(f"Build failed: {quote_path(str(exc))}")
                sys.exit(1)
            except OSError as exc:
                # The engine's walks report a per-entry failure and carry on, so
                # one that gets this far is a walk losing its footing: a
                # directory a step's leftovers moved out from under it, which
                # `dirfd.Levels` answers with ESTALE rather than reopening a
                # level somewhere else. A build, not an unexpected error.
                log_error(f"Build failed: {quote_path(exc.strerror or str(exc))}")
                sys.exit(1)

            arch_docker = ARCH_TO_DOCKER.get(target_arch, (target_arch, ""))[0]
            manifest, image_config = build_manifest_and_config(
                final_stage.image_config,
                final_stage.layers,
                arch_docker,
            )

            # One manifest cache entry per tag, so each can be installed
            # offline by name.
            for t in tags:
                try:
                    store_in_cache(t, target_arch, manifest, image_config)
                except OSError as exc:
                    log_error(f"Cannot write manifest cache for '{t}': {exc}")
                    sys.exit(1)

            for out_file in outputs:
                out_abs = os.path.abspath(os.path.expanduser(out_file))
                try:
                    if not quiet:
                        log_info(f"Writing OCI archive to '{out_abs}'...")
                    write_oci_archive(out_abs, manifest, image_config, primary_tag)
                except (OSError, RuntimeError) as exc:
                    log_error(f"Cannot write '{out_file}': {exc}")
                    sys.exit(1)

            if not quiet:
                total_size = sum(layer["size"] for layer in final_stage.layers)
                log_info("Build complete.")
                msg()
                msg(f"{C['CYAN']}Tag(s): {C['GREEN']}{', '.join(tags)}{C['RST']}")
                msg(
                    f"{C['CYAN']}Layers: {C['GREEN']}{len(final_stage.layers)} ({fmt_size(total_size)} total){C['RST']}"
                )
                msg()

            if install_as:
                _install_as_container(install_as, primary_tag, target_arch, quiet)

            if not outputs and not install_as and not quiet:
                msg(f"{C['CYAN']}Install with: {C['GREEN']}{PROGRAM_NAME} install {primary_tag}{C['RST']}")
                msg()
        except KeyboardInterrupt:
            log_error("Aborted by user.")
            sys.exit(1)
        finally:
            # The stage descriptors point inside the tree about to be removed,
            # and the run's own root descriptor is what they were made off.
            if engine is not None:
                engine.close()
            with contextlib.suppress(OSError):
                os.close(tmp_root_fd)
            _remove_build_tmp(tmp_root, tmp_parent_fd)


def _make_build_tmp() -> tuple[str, int, int]:
    """Create the scratch root a build assembles its stages in.

    Returns (path, a descriptor on the directory holding it, a descriptor on the
    root itself). The second is what the build addresses its own tree through:
    the stage directories, the ADD spool and the COPY --from rootfs are all made
    off it, so none of them is reached by resolving `tmp_root` again. `build-tmp`
    is a
    predictable name inside the runtime tree, which on Termux sits under the
    $TERMUX_PREFIX bound read-write into every non-isolated container, and
    `tempfile.mkdtemp(dir=...)` resolved it: a guest that left
    `build-tmp -> <host dir>` behind had every stage rootfs, every spooled ADD
    and every packed layer assembled inside that host directory. The name is
    walked down to with O_NOFOLLOW instead and this run's own root created with
    mkdirat off the descriptor that walk validated. What is made *inside* that
    root needs no walk of its own: the name is fresh and the mode is 0700.

    Both descriptors are kept for the length of the build: the removal at the end
    names the directory this created the root in rather than resolving
    `build-tmp` a second time, and the root's own descriptor outlives every stage
    that was made off it.

    A runtime tree that cannot hold the directory falls back to /tmp, as it
    always did.
    """
    build_tmp = os.path.join(RUNTIME_DIR, "build-tmp")
    with contextlib.suppress(OSError):
        os.makedirs(RUNTIME_DIR, exist_ok=True)
    dir_fd = dirfd.opendir_under(RUNTIME_DIR, ("build-tmp",), create=True)
    if dir_fd is None:
        warn(f"Failed to create build temporary directory '{build_tmp}', falling back to '/tmp'.")
        build_tmp = "/tmp"
        dir_fd = dirfd.opendir(build_tmp)
    try:
        name = f"cd-build-{os.getpid()}.{os.urandom(4).hex()}"
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        root_fd = dirfd.opendir_at(dir_fd, name)
    except OSError:
        os.close(dir_fd)
        raise
    return os.path.join(build_tmp, name), dir_fd, root_fd


def _remove_build_tmp(tmp_root: str, dir_fd: int) -> None:
    """Remove the build's scratch root under the descriptor it was created in.

    Going back to the name would resolve `build-tmp` again, and a guest that
    replaces it while the build runs would have the removal delete whatever the
    link points at. Removing under the descriptor also gets out a tree
    `shutil.rmtree(ignore_errors=True)` could not: it swallowed an OSError but
    not the RecursionError a deep one raised, and it could not chmod its way
    into a directory a build left sealed.
    """
    try:
        dirfd.rmtree_at(dir_fd, os.path.basename(tmp_root), force=True, on_error=lambda _rel, _exc: None)
    finally:
        os.close(dir_fd)


_SECRET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _resolve_build_isolation_mode() -> str:
    """Isolation mode for RUN steps: CD_USE_ISOLATION (max) wins over CD_USE_NS (ns)."""
    if use_isolation_env_enabled():
        return "max"
    if namespace.use_ns_env_enabled():
        return "ns"
    return "none"


def _parse_secret_opts(raw: list[str], tmp_root: str) -> dict[str, str]:
    """Parse --secret id=NAME[,src=PATH] items into {id: host_file_path}.

    Without src=, the secret value is taken from the environment variable
    named after the id and written to a 0400 file under tmp_root.
    """
    out: dict[str, str] = {}
    for item in raw:
        kv: dict[str, str] = {}
        for part in item.split(","):
            k, _, v = part.partition("=")
            kv[k.strip()] = v
        sid = kv.pop("id", "")
        src = kv.pop("src", None) or kv.pop("source", None)
        if not sid or kv or not _SECRET_ID_RE.match(sid):
            crit_error(f"invalid --secret '{item}' (expected id=NAME[,src=PATH]).")
            sys.exit(1)
        if src:
            path = os.path.abspath(os.path.expanduser(src))
            if not os.path.isfile(path):
                crit_error(f"--secret id={sid}: file '{src}' does not exist.")
                sys.exit(1)
        else:
            value = os.environ.get(sid)
            if value is None:
                crit_error(f"--secret id={sid}: no src= given and environment variable '{sid}' is not set.")
                sys.exit(1)
            path = os.path.join(tmp_root, f"cli-secret-{sid}")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            with os.fdopen(fd, "w") as fh:
                fh.write(value)
        out[sid] = path
    return out


def _parse_ssh_opts(raw: list[str]) -> dict[str, str]:
    """Parse --ssh [ID[=SOCK]] items into {id: socket_path}."""
    out: dict[str, str] = {}
    for item in raw:
        sid, _, sock = (item or "default").partition("=")
        sid = sid or "default"
        sock = sock or os.environ.get("SSH_AUTH_SOCK", "")
        if not sock:
            crit_error(f"--ssh {sid}: no socket path given and SSH_AUTH_SOCK is not set.")
            sys.exit(1)
        out[sid] = os.path.abspath(os.path.expanduser(sock))
    return out


def _parse_build_args(raw: list[str]) -> dict[str, str]:
    out = {}
    for item in raw:
        if "=" in item:
            k, _, v = item.partition("=")
            v = v.strip()
            if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
                v = v[1:-1]
        else:
            k, v = item, os.environ.get(item, "")
        if k:
            out[k] = v
    return out


def _derive_tag_from_path(build_dir: str, dockerfile: str) -> str:
    """Pick a default tag based on the build context basename."""
    base = os.path.basename(os.path.abspath(build_dir).rstrip("/"))
    if (not base or base in (".", "..")) and dockerfile and dockerfile != "-":
        base = os.path.basename(os.path.dirname(os.path.abspath(dockerfile)))
    base = base.lower()
    base = re.sub(r"[^a-z0-9_.\-]", "-", base).strip("-")
    base = re.sub(r"-+", "-", base)
    if not base or not is_valid_name(base):
        return ""
    return f"{base}:latest"


def _with_explicit_tag(tag: str) -> str:
    """Append ':latest' if `tag`'s last path component lacks a tag part."""
    last = tag.rsplit("/", maxsplit=1)[-1]
    return tag if ":" in last else tag + ":latest"


def _is_valid_tag(tag: str) -> bool:
    if not tag:
        return False
    if ":" in tag:
        name_part, tag_part = tag.rsplit(":", 1)
        if not tag_part:
            return False
        # Tag part: starts with alphanumeric, then word chars + dot/dash.
        if not re.match(r"^[A-Za-z0-9][\w.\-]*$", tag_part):
            return False
    else:
        name_part = tag
    last = name_part.split("/")[-1]
    return is_valid_name(last)


def _install_as_container(install_name: str, image_ref: str, target_arch: str, quiet: bool) -> None:
    """Run the install command for `image_ref` aliased as `install_name`."""
    if not quiet:
        log_info(f"Installing built image as '{install_name}'...")

    command_install(
        SimpleNamespace(
            image_ref=image_ref,
            custom_container_name=install_name,
            override_arch=target_arch,
        )
    )
