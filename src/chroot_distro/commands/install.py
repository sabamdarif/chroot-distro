# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Install a container from a registry image, a URL, or a local archive.

The three source kinds are told apart by the reference's shape alone: a leading `/`,
`./`, `../` or `~` is a local file, an `http://` or `https://` prefix a URL, anything
else a registry reference, which is then held to Docker's grammar before a name is
derived from it or a lock taken. Archive names come from the filename or URL path
with the longest recognized suffix stripped. A source without an inferable name
requires `--name`.

The container and rootfs are pinned for marker, metadata, extraction and guest
configuration writes. The marker is atomically published and synced before
creating a rootfs or clearing a retry. Failures retain marked data; retry clears
only children of the pinned rootfs. Completion verifies storage identities and syncs marker
removal, attempting restoration if finalization fails. These checks do not
prevent an active writer from changing names after the final check.

Ctrl+C ends in `os._exit` on purpose: `sys.exit` would run the `concurrent.futures`
atexit hook, which joins download workers that may each be blocked in a socket read for
the full timeout, long after the user asked to stop.

`reset` and `build` call `command_install` directly with a single reference string, while
the CLI parser hands it a list.
"""

import contextlib
import json
import os
import re
import sys
from urllib.parse import urlsplit

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import tempfile

from chroot_distro import dirfd
from chroot_distro.arch import get_device_cpu_arch, normalize_arch, platform_from_arch
from chroot_distro.atomic import atomic_write
from chroot_distro.commands.install_local import install_from_local_file
from chroot_distro.commands.login import find_login_shell
from chroot_distro.commands.login.env import read_manifest_has_command
from chroot_distro.commands.login.passwd import read_passwd_field
from chroot_distro.constants import (
    BASE_CACHE_DIR,
    DEFAULT_LAYER_DOWNLOAD_WORKERS,
    IS_TERMUX,
    PROGRAM_NAME,
    layer_download_workers,
)
from chroot_distro.exceptions import MountError
from chroot_distro.helpers.android import configure_android_rootfs
from chroot_distro.helpers.docker import InvalidReferenceError, derive_alias, parse_reference, pull_image
from chroot_distro.helpers.download import download_file
from chroot_distro.helpers.install_state import (
    clear_incomplete_rootfs,
    create_install_rootfs,
    finish_install,
    write_incomplete_marker,
)
from chroot_distro.helpers.rootfs import (
    register_android_ids,
    write_hosts,
    write_resolv_conf,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import C, crit_error, escape_controls, log_error, log_info, msg, quote_path
from chroot_distro.names import is_valid_name, require_valid_name
from chroot_distro.paths import (
    container_dir,
    container_incomplete_marker,
    container_manifest,
    container_rootfs,
    open_container_dir,
)
from chroot_distro.progress import clear_bar

# Compound OCI extensions must precede their plain tar suffixes.
_ARCHIVE_EXTS = (
    ".oci.tar.zstd",
    ".oci.tar.bz2",
    ".oci.tar.lzma",
    ".oci.tar.zst",
    ".oci.tar.xz",
    ".oci.tar.gz",
    ".oci.tar",
    ".tar.zstd",
    ".tar.zst",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.lzma",
    ".tlzma",
    ".tzst",
    ".tar",
)


def _is_local_path(ref: str) -> bool:
    """Return True if ref should be treated as a local file path."""
    if _is_url(ref):
        return False
    if ref.startswith(("/", "./", "../", "~")):
        return True
    low = ref.lower()
    return any(low.endswith(ext) for ext in _ARCHIVE_EXTS)


def _normalize_local_path(path: str) -> str:
    """Expand user and recover from accidental leading dots before absolute paths."""
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded) and expanded.startswith("./"):
        cleaned = "/" + expanded.lstrip("./")
        if os.path.isfile(cleaned):
            return cleaned
    return expanded


def _is_url(ref: str) -> bool:
    """Return True if ref is an HTTP/HTTPS URL."""
    return ref.startswith(("http://", "https://"))


def _derive_local_name(path: str) -> str:
    """Derive a container alias from an archive filename."""
    base = os.path.basename(path)
    low = base.lower()
    for ext in _ARCHIVE_EXTS:
        if low.endswith(ext):
            base = base[: -len(ext)]
            break
    base = re.sub(r"[^a-z0-9_.\-]", "-", base.lower())
    base = re.sub(r"^[^a-z0-9]+", "", base)
    return re.sub(r"-{2,}", "-", base).strip("-")


def command_install(args) -> None:
    """Install one or more containers from Docker images, URLs, or local archives."""
    # Internal callers (reset, build) pass a single string; the CLI parser
    # produces a list (nargs="*").
    refs = args.image_ref if isinstance(args.image_ref, list) else [args.image_ref]
    custom_container_name = getattr(args, "custom_container_name", None)

    if len(refs) > 1 and custom_container_name:
        crit_error("'--name' cannot be used when installing multiple images.")
        sys.exit(1)

    for ref in refs:
        _install_one(ref, args, custom_container_name)


def _install_one(image_ref: str, args, custom_container_name) -> None:
    """Install a single container from a Docker image, URL, or local archive."""

    if custom_container_name is not None and not custom_container_name:
        crit_error("container name can't be empty.")
        sys.exit(1)

    if custom_container_name:
        require_valid_name(custom_container_name)

    device_arch = get_device_cpu_arch()
    raw_arch = getattr(args, "override_arch", None)
    if raw_arch:
        dist_arch = normalize_arch(raw_arch)
        if dist_arch is None:
            crit_error(
                f"unknown architecture '{quote_path(raw_arch)}'. "
                f"Valid values: aarch64, arm, i686, riscv64, x86_64 "
                f"(or Docker format: linux/arm64, linux/amd64, "
                f"linux/arm/v7, linux/386, linux/riscv64)."
            )
            sys.exit(1)
    else:
        dist_arch = device_arch

    local_path = _normalize_local_path(image_ref) if _is_local_path(image_ref) else None
    url = image_ref if _is_url(image_ref) else None

    # Anything else is an image reference, and one Docker would refuse is refused
    # here, before a container name is derived from it or a lock taken: `Ubuntu`
    # used to reach the registry as a name no client can use.
    if local_path is None and url is None:
        try:
            parsed = parse_reference(image_ref)
        except InvalidReferenceError as exc:
            crit_error(f"cannot install '{quote_path(image_ref)}': {exc}.")
            sys.exit(1)
        if parsed.digest:
            crit_error(
                f"cannot install '{quote_path(image_ref)}': installing by digest is not "
                f"supported. Use a tag."
            )
            sys.exit(1)

    install_name = _resolve_install_name(
        image_ref,
        local_path,
        url,
        custom_container_name,
    )

    insecure = getattr(args, "insecure", False)

    with ContainerLock(install_name, exclusive=True, command="install"):
        _run_install(install_name, image_ref, local_path, url, dist_arch, insecure=insecure)


def _resolve_install_name(image_ref, local_path, url, custom_container_name):
    """Decide the on-disk container name. Exits on unresolvable cases."""
    if local_path is not None:
        if not os.path.isfile(local_path):
            crit_error(f"local file '{quote_path(local_path)}' does not exist or is not a regular file.")
            sys.exit(1)
        if custom_container_name:
            return custom_container_name
        derived = _derive_local_name(local_path)
        if not derived or not is_valid_name(derived):
            crit_error(
                f"cannot determine a valid container name from "
                f"'{quote_path(os.path.basename(local_path))}'. "
                f"Specify the name with '--name NAME'."
            )
            sys.exit(1)
        return derived

    if url is not None:
        try:
            source = urlsplit(url)
            host = source.hostname
            _ = source.port
            if not host or not host.isprintable() or any(char.isspace() for char in host):
                raise ValueError
        except ValueError:
            crit_error("invalid archive URL. Specify an HTTP or HTTPS URL with a valid host and port.")
            sys.exit(1)
        if custom_container_name:
            return custom_container_name
        derived = _derive_local_name(source.path)
        if not derived or not is_valid_name(derived):
            crit_error("cannot determine a valid container name from the URL path. Specify the name with '--name NAME'.")
            sys.exit(1)
        return derived

    derived = custom_container_name if custom_container_name else derive_alias(image_ref)
    if not is_valid_name(derived):
        crit_error(f"cannot derive a valid container name from '{image_ref}'. Specify the name with '--name NAME'.")
        sys.exit(1)
    return derived


_HINT_WIDTH = len("Run entrypoint:")


def _hint(label: str, command: str) -> None:
    msg(f"{C['CYAN']}{label:<{_HINT_WIDTH}} {C['GREEN']}{command}{C['RST']}")


def _print_start_hints(install_name: str, container_path: str, rootfs: str) -> None:
    """Print the commands that work on an installed tree.

    A rootfs with no shell takes the image's own Entrypoint/Cmd only, so a
    login line there would name a command that always fails.
    """
    login_shell = read_passwd_field(rootfs, "root", 6) or "/bin/sh"
    if find_login_shell(rootfs, container_path, login_shell) is not None:
        _hint("Start shell:", f"{PROGRAM_NAME} login {install_name}")
    if read_manifest_has_command(container_path):
        _hint("Run entrypoint:", f"{PROGRAM_NAME} run {install_name}")


def _run_install(
    install_name: str,
    image_ref: str,
    local_path,
    url,
    dist_arch: str,
    insecure: bool = False,
) -> None:
    """Inner install logic, called with the container lock already held."""
    container_path = container_dir(install_name)
    rootfs_dir = container_rootfs(install_name)
    incomplete_marker = container_incomplete_marker(install_name)

    marker = os.path.basename(incomplete_marker)
    rootfs_leaf = os.path.basename(rootfs_dir)
    manifest_leaf = os.path.basename(container_manifest(install_name))
    container_fd = None
    rootfs_fd = None
    tmp_archive = None
    interrupted = False
    try:
        container_fd = open_container_dir(install_name, create=True)
        try:
            dirfd.lstat_at(container_fd, marker)
        except FileNotFoundError:
            incomplete = False
        else:
            incomplete = True
        with contextlib.suppress(FileNotFoundError):
            rootfs_fd = dirfd.opendir_at(container_fd, rootfs_leaf)

        if rootfs_fd is not None and not incomplete:
            msg()
            crit_error(f"container '{install_name}' already exists. Specify a different name with '--name NAME'.")
            msg()
            _print_start_hints(install_name, container_path, rootfs_dir)
            _hint("Reinstall:", f"{PROGRAM_NAME} reset {install_name}")
            _hint("Uninstall:", f"{PROGRAM_NAME} remove {install_name}")
            msg()
            sys.exit(1)

        if local_path is not None:
            log_info(f"Installing from '{quote_path(os.path.basename(local_path))}' as '{install_name}'...")
        elif url is not None:
            log_info(f"Installing archive from URL as '{install_name}'...")
        else:
            last_component = image_ref.rsplit("/", maxsplit=1)[-1]
            display_ref = image_ref if ":" in last_component else f"{image_ref}:latest"
            log_info(f"Installing '{display_ref}' as '{install_name}'...")
            workers = layer_download_workers()
            if workers != DEFAULT_LAYER_DOWNLOAD_WORKERS:
                log_info(f"Parallel download workers: {workers}")

        if rootfs_fd is None:
            rootfs_fd = create_install_rootfs(container_fd, rootfs_leaf, marker, incomplete=incomplete)
        else:
            write_incomplete_marker(marker, dir_fd=container_fd)
            log_info(f"Found remnants of an interrupted install of '{install_name}'; removing and reinstalling...")
            clear_incomplete_rootfs(install_name, container_fd, rootfs_fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(manifest_leaf, dir_fd=container_fd)

        if local_path is not None:
            log_info("Extracting rootfs from archive...")
            metadata = install_from_local_file(local_path, rootfs_fd, dist_arch)
        elif url is not None:
            os.makedirs(BASE_CACHE_DIR, exist_ok=True)
            fd, tmp_archive = tempfile.mkstemp(
                prefix=f"dl_install_{install_name}.",
                suffix=".tmp",
                dir=BASE_CACHE_DIR,
            )
            os.close(fd)
            log_info("Downloading archive...")
            try:
                download_file(url, tmp_archive, insecure=insecure)
            except (OSError, RuntimeError) as exc:
                source = urlsplit(url)
                if source.username is not None or source.query or source.fragment:
                    raise RuntimeError("could not download the archive from the supplied URL.") from exc
                raise
            log_info("Extracting rootfs from archive...")
            metadata = install_from_local_file(tmp_archive, rootfs_fd, dist_arch)
        else:
            os.makedirs(BASE_CACHE_DIR, exist_ok=True)
            metadata = pull_image(image_ref, rootfs_fd, platform_from_arch(dist_arch), insecure=insecure)

        if metadata is not None:
            manifest_data = {
                "image_ref": (metadata.get("image_ref") or (image_ref if local_path is None else "")),
                "arch": metadata.get("arch") or dist_arch,
                "manifest": metadata.get("manifest", {}),
                "image_config": metadata.get("image_config", {}),
            }
            try:
                with atomic_write(manifest_leaf, mode=0o644, dir_fd=container_fd) as fh:
                    json.dump(manifest_data, fh, indent=2)
            except OSError as exc:
                crit_error(f"could not write manifest.json for '{install_name}': {escape_controls(str(exc))}")
                sys.exit(1)

        try:
            etc_fd = dirfd.opendir_at(rootfs_fd, "etc")
        except OSError:
            etc_fd = None
        if etc_fd is not None:
            os.close(etc_fd)
            log_info("Updating '/etc/resolv.conf'...")
            write_resolv_conf(rootfs_dir, root_fd=rootfs_fd)

            log_info("Updating '/etc/hosts'...")
            write_hosts(rootfs_dir, root_fd=rootfs_fd)

        if IS_TERMUX:
            log_info("Registering Android-specific UIDs and GIDs...")
            register_android_ids(rootfs_dir, root_fd=rootfs_fd)
            configure_android_rootfs(rootfs_dir, root_fd=rootfs_fd)

        finish_install(install_name, container_fd, rootfs_fd, marker)
    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        interrupted = True
    except (EOFError, OSError, tarfile.TarError, RuntimeError, MountError) as exc:
        clear_bar()
        log_error(f"Failed to install: {escape_controls(str(exc))}")
        sys.exit(1)
    finally:
        if rootfs_fd is not None:
            os.close(rootfs_fd)
        if container_fd is not None:
            os.close(container_fd)
        if tmp_archive is not None:
            with contextlib.suppress(OSError):
                os.remove(tmp_archive)

    if interrupted:
        for stream in (sys.stdout, sys.stderr):
            if stream is not None:
                with contextlib.suppress(OSError, ValueError):
                    stream.flush()
        os._exit(1)

    log_info("Finished installation.")
    msg()
    _print_start_hints(install_name, container_path, rootfs_dir)
    msg()
