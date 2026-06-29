"""Native Linux syscall wrappers for chroot-distro.

This package provides pure-Python/ctypes replacements for the external
binaries ``chroot``, ``mount``, ``umount``, ``unshare``, and ``nsenter``.
All functions call the corresponding Linux syscalls directly via ``ctypes``
and do **not** shell out to any external binary.

Submodules
----------
_libc
    Shared libc handle, errno helper, and Python 3.10–3.11 backports for
    ``os.unshare`` / ``os.setns``.
_constants
    Linux kernel constants (mount flags, namespace flags, capabilities).
chroot
    ``chroot(2)`` + user/group switching + exec.
mount
    ``mount(2)`` wrappers for bind mounts, filesystem mounts, propagation.
umount
    ``umount2(2)`` wrapper.
unshare
    ``unshare(2)`` + fork for namespace creation.
nsenter
    ``setns(2)`` for entering existing namespaces.
"""

from __future__ import annotations

from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNS,
    CLONE_NEWNET,
    CLONE_NEWPID,
    CLONE_NEWTIME,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    MNT_DETACH,
    MNT_FORCE,
    MS_BIND,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_RDONLY,
    MS_REC,
    MS_REMOUNT,
    MS_SHARED,
    MS_SLAVE,
    S_IFCHR,
)

__all__ = [
    # Mount flags
    "MS_RDONLY",
    "MS_NOSUID",
    "MS_NODEV",
    "MS_NOEXEC",
    "MS_REMOUNT",
    "MS_BIND",
    "MS_REC",
    "MS_PRIVATE",
    "MS_SLAVE",
    "MS_SHARED",
    # Umount flags
    "MNT_FORCE",
    "MNT_DETACH",
    # Clone/namespace flags
    "CLONE_NEWTIME",
    "CLONE_NEWNS",
    "CLONE_NEWCGROUP",
    "CLONE_NEWUTS",
    "CLONE_NEWIPC",
    "CLONE_NEWUSER",
    "CLONE_NEWPID",
    "CLONE_NEWNET",
    # Misc
    "S_IFCHR",
]
