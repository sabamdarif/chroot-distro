import os
import re
import shutil
import sys
import tempfile
import typing
from contextlib import ExitStack
from types import SimpleNamespace

from chroot_distro.arch import get_device_cpu_arch, normalize_arch
from chroot_distro.commands.install import command_install
from chroot_distro.constants import (
    PROGRAM_NAME,
    RUNTIME_DIR,
)
from chroot_distro.helpers.build_engine import (
    BuildEngine,
    BuildError,
)
from chroot_distro.helpers.docker import ARCH_TO_DOCKER
from chroot_distro.helpers.dockerfile import (
    DockerfileSyntaxError,
    parse_dockerfile,
)
from chroot_distro.helpers.oci_writer import (
    build_manifest_and_config,
    store_in_cache,
    write_oci_archive,
)
from chroot_distro.locking import BuildLock
from chroot_distro.message import C, crit_error, log_error, log_info, msg
from chroot_distro.names import is_valid_name, require_valid_name
from chroot_distro.paths import container_rootfs
from chroot_distro.progress import fmt_size

# ---------------------------------------------------------------------------
# Top-level command
# ---------------------------------------------------------------------------

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

    # ----- resolve build context + Dockerfile -----
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

    # ----- read + parse Dockerfile -----
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

    # ----- target architecture -----
    if override_arch:
        target_arch = normalize_arch(override_arch)
        if target_arch is None:
            crit_error(f"unknown architecture '{override_arch}'.")
            sys.exit(1)
    else:
        target_arch = get_device_cpu_arch()

    # ----- Validate install-as container name -----
    if install_as:
        require_valid_name(install_as, kind="--install-as value")

        if os.path.isdir(container_rootfs(install_as)):
            crit_error(
                f"container '{install_as}' defined by --install-as already "
                f"exists. Use '{PROGRAM_NAME} remove {install_as}' first or "
                f"'{PROGRAM_NAME} reset {install_as}' to rebuild."
            )
            sys.exit(1)

    # ----- determine the canonical tag set -----
    if not tags:
        derived = _derive_tag_from_path(build_dir, dockerfile)
        if not derived:
            crit_error(
                "cannot derive a tag from the build path. Pass '--tag' "
                "explicitly (e.g. --tag myapp:latest)."
            )
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

    # ----- refuse to overwrite existing output files -----
    for out_file in outputs:
        out_abs = os.path.abspath(os.path.expanduser(out_file))
        if os.path.exists(out_abs):
            crit_error(
                f"file '{out_abs}' already exists. "
                f"Please specify a different name."
            )
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

        # ----- run the build -----
        build_tmp = os.path.join(RUNTIME_DIR, "build-tmp")
        try:
            os.makedirs(build_tmp, exist_ok=True)
        except OSError:
            build_tmp = "/tmp"  # Fallback just in case
        tmp_root = tempfile.mkdtemp(prefix="cd-build-", dir=build_tmp)

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
        )

        try:
            try:
                final_stage = engine.run(instructions)
            except BuildError as exc:
                log_error(f"Build failed: {exc}")
                sys.exit(1)

            # ----- assemble manifest + image_config -----
            arch_docker = ARCH_TO_DOCKER.get(target_arch, (target_arch, ""))[0]
            manifest, image_config = build_manifest_and_config(
                final_stage.image_config,
                final_stage.layers,
                arch_docker,
            )

            # Write the manifest cache for every tag so each can be
            # installed offline by name.
            for t in tags:
                try:
                    store_in_cache(t, target_arch, manifest, image_config)
                except OSError as exc:
                    log_error(f"Cannot write manifest cache for '{t}': {exc}")
                    sys.exit(1)

            # OCI tarball outputs.
            for out_file in outputs:
                out_abs = os.path.abspath(os.path.expanduser(out_file))
                try:
                    if not quiet:
                        log_info(f"Writing OCI archive to '{out_abs}'...")
                    write_oci_archive(out_abs, manifest, image_config, primary_tag)
                except (OSError, RuntimeError) as exc:
                    log_error(f"Cannot write '{out_file}': {exc}")
                    sys.exit(1)

            # Build summary.
            if not quiet:
                total_size = sum(layer["size"] for layer in final_stage.layers)
                log_info("Build complete.")
                msg()
                msg(f"{C['CYAN']}Tag(s): "
                    f"{C['GREEN']}{', '.join(tags)}{C['RST']}")
                msg(f"{C['CYAN']}Layers: "
                    f"{C['GREEN']}{len(final_stage.layers)}"
                    f" ({fmt_size(total_size)} total){C['RST']}")
                msg()

            # Optional --install-as: install the built image as a
            # container directly.
            if install_as:
                _install_as_container(install_as, primary_tag, target_arch, quiet)

            # Final hint when no --output and no --install-as were given.
            if not outputs and not install_as and not quiet:
                msg(f"{C['CYAN']}Install with: "
                    f"{C['GREEN']}{PROGRAM_NAME} install {primary_tag}{C['RST']}")
                msg()
        except KeyboardInterrupt:
            log_error("Aborted by user.")
            sys.exit(1)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _parse_build_args(raw: list[str]) -> dict[str, str]:
    out = {}
    for item in raw:
        if "=" in item:
            k, _, v = item.partition("=")
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
