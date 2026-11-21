# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Publish install and restore state while holding the container's exclusive lock.

The marker is synced before rootfs writes. A retry clears only the pinned,
unmounted rootfs. Completion checks that both directories still occupy their
original names before and after syncing marker removal.
"""

import errno
import os

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.helpers.mount_manager import refuse_rootfs_mounts
from chroot_distro.message import escape_controls, log_error
from chroot_distro.paths import container_rootfs, open_container_dir


def write_incomplete_marker(marker: str, *, dir_fd: int) -> None:
    with atomic_write(marker, mode=0o644, dir_fd=dir_fd):
        pass


def create_install_rootfs(container_fd: int, rootfs: str, marker: str, *, incomplete: bool) -> int:
    """Mark the operation, then create a rootfs without adopting a competing directory."""
    marker_fd = None
    try:
        with atomic_write(marker, mode=0o644, dir_fd=container_fd, replace=incomplete) as fh:
            marker_fd = os.dup(fh.fileno())
        try:
            os.mkdir(rootfs, dir_fd=container_fd)
        except FileExistsError:
            # A later retry must not take a competing directory for our partial rootfs.
            if not incomplete and os.path.samestat(os.fstat(marker_fd), dirfd.lstat_at(container_fd, marker)):
                os.unlink(marker, dir_fd=container_fd)
                os.fsync(container_fd)
            raise
        return dirfd.opendir_at(container_fd, rootfs)
    finally:
        if marker_fd is not None:
            os.close(marker_fd)


def _check_identity(name: str, container_fd: int, rootfs_fd: int) -> None:
    current_fd = open_container_dir(name)
    try:
        current_rootfs = dirfd.opendir_at(current_fd, os.path.basename(container_rootfs(name)))
        try:
            if not (
                os.path.samestat(os.fstat(current_fd), os.fstat(container_fd))
                and os.path.samestat(os.fstat(current_rootfs), os.fstat(rootfs_fd))
            ):
                raise OSError(errno.ESTALE, "container storage was replaced")
        finally:
            os.close(current_rootfs)
    finally:
        os.close(current_fd)


def clear_incomplete_rootfs(name: str, container_fd: int, rootfs_fd: int) -> None:
    refuse_rootfs_mounts(rootfs_fd)
    _check_identity(name, container_fd, rootfs_fd)
    for child in dirfd.listdir_at(rootfs_fd):
        dirfd.rmtree_at(rootfs_fd, child, force=True)


def finish_install(name: str, container_fd: int, rootfs_fd: int, marker: str) -> None:
    try:
        _check_identity(name, container_fd, rootfs_fd)
        os.unlink(marker, dir_fd=container_fd)
        os.fsync(container_fd)
        _check_identity(name, container_fd, rootfs_fd)
    except BaseException:
        try:
            write_incomplete_marker(marker, dir_fd=container_fd)
        except OSError as exc:
            log_error(f"Could not restore the incomplete install marker: {escape_controls(str(exc))}")
        raise
