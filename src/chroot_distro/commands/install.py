import contextlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile

from chroot_distro.arch import get_device_cpu_arch, normalize_arch
from chroot_distro.atomic import atomic_replace
from chroot_distro.commands.install_local import install_from_local_file
from chroot_distro.constants import BASE_CACHE_DIR, PROGRAM_NAME
from chroot_distro.helpers.android import configure_android_rootfs
from chroot_distro.helpers.docker import derive_alias, pull_image
from chroot_distro.helpers.download import download_file
from chroot_distro.helpers.rootfs import (
    register_android_ids,
    write_hosts,
    write_resolv_conf,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import C, crit_error, log_error, log_info, msg
from chroot_distro.names import is_valid_name, require_valid_name
from chroot_distro.paths import (
    container_dir,
    container_manifest,
    container_rootfs,
)
from chroot_distro.progress import clear_bar

# Archive extensions stripped when deriving a container name from a filename.
_ARCHIVE_EXTS = (
    ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
    ".oci.tar.xz", ".oci.tar.gz", ".oci.tar",
    ".tar.lzma", ".tlzma", ".tar",
)


def _is_local_path(ref: str) -> bool:
    """Return True if ref should be treated as a local file path."""
    return ref.startswith(("/", "./", "../", "~"))


def _is_url(ref: str) -> bool:
    """Return True if ref is an HTTP/HTTPS URL."""
    return ref.startswith(("http://", "https://"))


def _derive_local_name(path: str) -> str:
    """Derive a container alias from an archive filename."""
    base = os.path.basename(path)
    low = base.lower()
    for ext in _ARCHIVE_EXTS:
        if low.endswith(ext):
            base = base[:-len(ext)]
            break
    base = re.sub(r"[^a-z0-9_.\-]", "-", base.lower())
    base = re.sub(r"^[^a-z0-9]+", "", base)
    return re.sub(r"-{2,}", "-", base).strip("-")


def command_install(args) -> None:
    """Install a container from a Docker image, URL, or local archive."""
    image_ref = args.image_ref
    custom_container_name = getattr(args, "custom_container_name", None)

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
            crit_error(f"unknown architecture '{raw_arch}'. "
                       f"Valid values: aarch64, arm, i686, riscv64, x86_64 "
                       f"(or Docker format: linux/arm64, linux/amd64, "
                       f"linux/arm/v7, linux/386, linux/riscv64).")
            sys.exit(1)
    else:
        dist_arch = device_arch

    local_path = os.path.expanduser(image_ref) if _is_local_path(image_ref) else None
    url = image_ref if _is_url(image_ref) else None

    install_name = _resolve_install_name(
        image_ref, local_path, url, custom_container_name,
    )

    with ContainerLock(install_name, exclusive=True, command="install"):
        _run_install(install_name, image_ref, local_path, url, dist_arch)


def _resolve_install_name(image_ref, local_path, url, custom_container_name):
    """Decide the on-disk container name. Exits on unresolvable cases."""
    if local_path is not None:
        if not os.path.isfile(local_path):
            crit_error(f"local file '{local_path}' does not exist "
                       f"or is not a regular file.")
            sys.exit(1)
        if custom_container_name:
            return custom_container_name
        derived = _derive_local_name(local_path)
        if not derived or not is_valid_name(derived):
            crit_error(f"cannot determine a valid container name from "
                       f"'{os.path.basename(local_path)}'. "
                       f"Specify the name with '--name NAME'.")
            sys.exit(1)
        return derived

    if url is not None:
        if custom_container_name:
            return custom_container_name
        url_path = url.split("?")[0].split("#")[0]
        derived = _derive_local_name(url_path)
        if not derived or not is_valid_name(derived):
            crit_error(f"cannot determine a valid container name from "
                       f"'{url}'. Specify the name with '--name NAME'.")
            sys.exit(1)
        return derived

    derived = custom_container_name if custom_container_name else derive_alias(image_ref)
    if not is_valid_name(derived):
        crit_error(f"cannot derive a valid container name from "
                   f"'{image_ref}'. Specify the name with '--name NAME'.")
        sys.exit(1)
    return derived


def _run_install(
    install_name: str,
    image_ref: str,
    local_path,
    url,
    dist_arch: str,
) -> None:
    """Inner install logic — called with the container lock already held."""
    container_path = container_dir(install_name)
    rootfs_dir = container_rootfs(install_name)

    if os.path.isdir(rootfs_dir):
        msg()
        crit_error(f"container '{install_name}' already exists. "
                   f"Specify a different name with '--name NAME'.")
        msg()
        msg(f"{C['CYAN']}Start shell: "
            f"{C['GREEN']}{PROGRAM_NAME} login {install_name}{C['RST']}")
        msg(f"{C['CYAN']}Reinstall:   "
            f"{C['GREEN']}{PROGRAM_NAME} reset {install_name}{C['RST']}")
        msg(f"{C['CYAN']}Uninstall:   "
            f"{C['GREEN']}{PROGRAM_NAME} remove {install_name}{C['RST']}")
        msg()
        sys.exit(1)

    if local_path is not None:
        log_info(f"Installing from '{os.path.basename(local_path)}' "
                 f"as '{install_name}'...")
    elif url is not None:
        log_info(f"Installing from URL '{url}' as '{install_name}'...")
    else:
        last_component = image_ref.rsplit("/", maxsplit=1)[-1]
        display_ref = (
            image_ref if ":" in last_component else f"{image_ref}:latest"
        )
        log_info(f"Installing '{display_ref}' as '{install_name}'...")

    os.makedirs(rootfs_dir, exist_ok=True)

    def _cleanup() -> None:
        with contextlib.suppress(OSError):
            shutil.rmtree(container_path)

    tmp_archive = None
    try:
        if local_path is not None:
            log_info("Extracting rootfs from archive...")
            metadata = install_from_local_file(local_path, rootfs_dir, dist_arch)
        elif url is not None:
            os.makedirs(BASE_CACHE_DIR, exist_ok=True)
            fd, tmp_archive = tempfile.mkstemp(
                prefix=f"dl_install_{install_name}.",
                suffix=".tmp",
                dir=BASE_CACHE_DIR,
            )
            os.close(fd)
            log_info("Downloading archive...")
            download_file(url, tmp_archive)
            log_info("Extracting rootfs from archive...")
            metadata = install_from_local_file(tmp_archive, rootfs_dir, dist_arch)
        else:
            os.makedirs(BASE_CACHE_DIR, exist_ok=True)
            metadata = pull_image(image_ref, rootfs_dir, dist_arch)

        # Write manifest.json when metadata is available
        if metadata is not None:
            manifest_data = {
                "image_ref": (
                    metadata.get("image_ref") or
                    (image_ref if local_path is None else "")
                ),
                "arch": metadata.get("arch") or dist_arch,
                "manifest": metadata.get("manifest", {}),
                "image_config": metadata.get("image_config", {}),
            }
            try:
                with atomic_replace(container_manifest(install_name)) as tmp, open(tmp, "w") as fh:
                    json.dump(manifest_data, fh, indent=2)
            except OSError as exc:
                log_error(f"Warning: could not write manifest.json: {exc}")

        if os.path.isdir(os.path.join(rootfs_dir, "etc")):
            log_info("Updating '/etc/resolv.conf'...")
            write_resolv_conf(rootfs_dir)

            log_info("Updating '/etc/hosts'...")
            write_hosts(rootfs_dir)

            if os.path.isfile(os.path.join(rootfs_dir, "etc", "passwd")):
                log_info("Registering Android-specific UIDs and GIDs...")
                register_android_ids(rootfs_dir)
                configure_android_rootfs(rootfs_dir)

    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        _cleanup()
        sys.exit(1)
    except (EOFError, OSError, tarfile.TarError, RuntimeError) as exc:
        clear_bar()
        log_error(f"Failed to install: {exc}")
        _cleanup()
        sys.exit(1)
    except Exception:
        _cleanup()
        raise
    finally:
        if tmp_archive is not None:
            with contextlib.suppress(OSError):
                os.remove(tmp_archive)

    log_info("Finished installation.")
    msg()
    entrypoint = (
        (metadata.get("image_config") or {}).get("config", {}).get("Entrypoint")
        if metadata else None
    )
    shell_label = "Start shell:   " if entrypoint else "Start shell:"
    msg(f"{C['CYAN']}{shell_label} "
        f"{C['GREEN']}{PROGRAM_NAME} login {install_name}{C['RST']}")
    if entrypoint:
        msg(f"{C['CYAN']}Run entrypoint: "
            f"{C['GREEN']}{PROGRAM_NAME} run {install_name}{C['RST']}")
    msg()
