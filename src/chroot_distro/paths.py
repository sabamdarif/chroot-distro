import os

from chroot_distro.constants import CONTAINERS_DIR
from chroot_distro.exceptions import (
    ChrootDistroError,
    ContainerNotFoundError,
    InvalidNameError,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.names import is_valid_name


def container_dir(name: str) -> str:
    """Return the absolute path to a container's top-level directory."""
    return os.path.join(CONTAINERS_DIR, name)


def container_rootfs(name: str) -> str:
    """Return the absolute path to a container's rootfs directory."""
    return os.path.join(container_dir(name), "rootfs")


def container_manifest(name: str) -> str:
    """Return the absolute path to a container's manifest.json sentinel."""
    return os.path.join(container_dir(name), "manifest.json")


def container_from_spec(spec: str) -> str | None:
    """Return the container name in a `name:path` spec, or None."""
    return spec.split(":", 1)[0] if ":" in spec else None


def resolve_container_path(spec: str) -> str:
    """Resolve a `name:path` or plain host path to an absolute host path.

    For a `name:path` spec the result is forced to stay inside the
    container's rootfs — an attempt to traverse out with `..` segments
    is rejected.
    """
    if ":" not in spec:
        return os.path.normpath(os.path.abspath(spec))

    name, _, rel_path = spec.partition(":")
    if not is_valid_name(name):
        raise InvalidNameError(f"invalid container name '{name}' in spec '{spec}'.")
    rootfs = os.path.normpath(container_rootfs(name))
    if not os.path.isdir(rootfs):
        raise ContainerNotFoundError(f"container '{name}' does not exist.")
    resolved = os.path.normpath(os.path.join(rootfs, rel_path.lstrip("/")))
    if resolved != rootfs and not resolved.startswith(rootfs + os.sep):
        raise ChrootDistroError("destination path escapes the container directory.")
    return resolved


def container_locks_for_spec_pair(src_spec: str, dst_spec: str, command: str) -> list[ContainerLock]:
    """Return ContainerLock instances needed for a `src -> dst` op."""
    src_name = container_from_spec(src_spec)
    dst_name = container_from_spec(dst_spec)
    if src_name and dst_name:
        if src_name == dst_name:
            return [ContainerLock(src_name, exclusive=True, command=command)]
        return [
            ContainerLock(name, exclusive=(name == dst_name), command=command)
            for name in sorted({src_name, dst_name})
        ]
    if dst_name:
        return [ContainerLock(dst_name, exclusive=True, command=command)]
    if src_name:
        return [ContainerLock(src_name, exclusive=False, command=command)]
    return []
