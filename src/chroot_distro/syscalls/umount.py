# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Unmount a filesystem through umount2(2).

One function. `lazy` (MNT_DETACH) detaches the mount from the tree at once and
lets the kernel clean it up when the last reference drops, which is what teardown
after a session wants, since a process may still hold a file open under it.
`force` (MNT_FORCE) aborts pending requests instead, and only means anything on a
network filesystem.
"""

from __future__ import annotations

from chroot_distro.syscalls._constants import MNT_DETACH, MNT_FORCE
from chroot_distro.syscalls._libc import libc_umount2

__all__ = [
    "MNT_DETACH",
    "MNT_FORCE",
    "native_umount",
]


def native_umount(target: str, *, lazy: bool = False, force: bool = False) -> None:
    """Unmount the filesystem at *target* via ``umount2(2)``.

    By default the call performs a regular (synchronous) unmount.  The
    *lazy* and *force* flags can be combined if needed, although in
    practice one or the other is used.

    Args:
        target: The mount-point to unmount.
        lazy: If ``True``, perform a lazy unmount (``MNT_DETACH``).
            The mount-point is immediately disconnected from the
            filesystem hierarchy and all references are cleaned up
            when the last process stops using it.  This is the
            safest option when tearing down a chroot that may still
            have open file descriptors.
        force: If ``True``, force the unmount (``MNT_FORCE``).
            This can interrupt pending I/O and may cause data loss
            on real (non-virtual) filesystems.  Primarily useful for
            NFS mounts that have become unreachable.

    Raises:
        OSError: If the underlying ``umount2(2)`` call fails (e.g.
            *target* is not mounted, or the caller lacks
            ``CAP_SYS_ADMIN``).

    Example:
        >>> native_umount("/chroot/proc")
        >>> native_umount("/chroot/dev", lazy=True)
        >>> native_umount("/mnt/nfs", force=True)
    """
    flags = 0
    if lazy:
        flags |= MNT_DETACH
    if force:
        flags |= MNT_FORCE

    libc_umount2(target.encode(), flags)
