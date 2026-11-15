# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro remove`: stop the container, unmount it, delete both its trees.

Remove `containers/<name>/` and the per-container runtime state under
`data/<name>/`. Keep the lock file because another command may already
have it open when `remove` releases its flock.

Sessions end the way `unmount` ends them, SIGTERM and then SIGKILL after a grace
period, and a container with a process or a mount still standing afterwards is
refused rather than deleted from under it.

Deletion and progress counting use the bounded descriptor walkers in `dirfd`.
`remove` pins both storage parents through the platform-anchor walk and refuses
an initially linked container or rootfs before teardown. Runtime data goes first:
its deletion failure keeps the container available for retry. Unlinking a file
never changes its permissions, including when it is hardlinked outside the tree.
`commands/reset.py` retains the path form of `_remove_path`; that form opens its
parent by path and does not validate the storage ancestors.
"""

import contextlib
import os
import signal
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro import dirfd
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_error, log_info, quote_path
from chroot_distro.names import require_valid_name
from chroot_distro.paths import (
    container_data_dir,
    container_dir,
    container_rootfs,
    open_containers_dir,
    open_runtime_data_dir,
)


def _remove_path(path: str, on_remove=None, *, dir_fd: int | None = None) -> bool:
    """Remove one entry beneath a retained parent, reporting display paths."""
    parent, name = os.path.split(os.path.normpath(path))
    try:
        with contextlib.ExitStack() as pins:
            if dir_fd is None:
                dir_fd = dirfd.opendir(parent or os.curdir)
                pins.callback(os.close, dir_fd)

            def _removed(rel: str) -> None:
                if on_remove is not None:
                    on_remove(os.path.join(path, rel) if rel else path)

            return dirfd.rmtree_at(dir_fd, name, force=True, on_remove=_removed, on_error=lambda _rel, _exc: None)
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _count_files(path: str, *, dir_fd: int | None = None) -> int:
    """Count a tree including directories, without following links."""
    parent, name = os.path.split(os.path.normpath(path))
    try:
        with contextlib.ExitStack() as pins:
            if dir_fd is None:
                dir_fd = dirfd.opendir(parent or os.curdir)
                pins.callback(os.close, dir_fd)
            fd = dirfd.opendir_at(dir_fd, name)
            pins.callback(os.close, fd)
            return 1 + dirfd.count_tree_at(fd, include_dirs=True)
    except OSError:
        return 1


def command_remove(args) -> None:
    """Delete one or more installed containers."""
    # Internal callers pass a single string; the CLI parser produces a list.
    names = args.container_name if isinstance(args.container_name, list) else [args.container_name]
    verbose = getattr(args, "verbose", False)
    for name in names:
        _remove_one(name, verbose)


def _remove_one(container_name: str, verbose: bool) -> None:
    """Delete an installed container's directory tree after stopping running sessions and unmounting."""
    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)

    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    with ContainerLock(container_name, exclusive=True, command="remove"), contextlib.ExitStack() as pins:
        try:
            containers_fd = open_containers_dir()
            pins.callback(os.close, containers_fd)
            rootfs_fd = dirfd.descend_at(containers_fd, (container_name, "rootfs"))
            pins.callback(os.close, rootfs_fd)
        except OSError as exc:
            raise ChrootDistroError(f"Cannot open storage for container '{container_name}': {exc}") from exc

        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            log_info(f"Stopping active sessions/processes in container '{container_name}' (PIDs: {active_pids})...")

            for pid in active_pids:
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)

            start_time = time.time()
            while time.time() - start_time < 2.0:
                remaining_pids = session.get_active_chroot_pids(container_name)
                if not remaining_pids:
                    break
                time.sleep(0.1)

            remaining_pids = session.get_active_chroot_pids(container_name)
            if remaining_pids:
                log_info(f"Processes {remaining_pids} did not exit. Sending SIGKILL...")
                for pid in remaining_pids:
                    with contextlib.suppress(OSError):
                        os.kill(pid, signal.SIGKILL)

                start_time = time.time()
                while time.time() - start_time < 1.0:
                    remaining_pids = session.get_active_chroot_pids(container_name)
                    if not remaining_pids:
                        break
                    time.sleep(0.1)

        session.reset(container_name)
        session.clear_mount_options(container_name)

        holder = namespace.get_live_holder(container_name)

        with contextlib.suppress(Exception):
            mount_manager.unmount_all(rootfs_dir, holder=holder)

        if holder is not None:
            namespace.release_holder(container_name)
            namespace.clear_isolation_mode(container_name)
            holder = None

        remaining_pids = session.get_active_chroot_pids(container_name)
        remaining_mounts = mount_manager.get_active_mounts(rootfs_dir)
        if remaining_pids or remaining_mounts:
            crit_error(
                f"Cannot remove container '{container_name}': the distro is busy. "
                "Kill any running processes and try again."
            )
            sys.exit(1)

        try:
            data_fd = open_runtime_data_dir()
        except FileNotFoundError:
            data_fd = None
        except OSError as exc:
            raise ChrootDistroError(f"Cannot open runtime data for container '{container_name}': {exc}") from exc
        if data_fd is not None:
            pins.callback(os.close, data_fd)

        log_info(f"Removing container '{container_name}'...")

        from collections.abc import Callable

        from chroot_distro.progress import clear_bar, draw_count_bar, progress_active

        show_progress = progress_active() and not verbose
        total_files = 0
        container_path = container_dir(container_name)
        data_path = container_data_dir(container_name)
        if show_progress:
            total_files = _count_files(container_path, dir_fd=containers_fd)
            if data_fd is not None and dirfd.exists_at(data_fd, container_name):
                total_files += _count_files(data_path, dir_fd=data_fd)

        removed_count = 0

        on_remove: Callable[[str], None] | None = None
        if verbose or show_progress:

            def _on_remove(path: str) -> None:
                nonlocal removed_count
                removed_count += 1
                if verbose:
                    log_info(f"Removed: '{quote_path(path)}'")
                elif show_progress:
                    draw_count_bar(removed_count, total_files, label="Removing", unit="files")

            on_remove = _on_remove

        try:
            if data_fd is not None and not _remove_path(data_path, on_remove, dir_fd=data_fd):
                log_error("Failed to remove runtime data. The container was kept; retry removal.")
                sys.exit(1)
            if not _remove_path(container_path, on_remove, dir_fd=containers_fd):
                log_error("Finished with errors. Some files probably were not deleted.")
                sys.exit(1)
        finally:
            if show_progress:
                clear_bar()

    log_info("Finished removing the container.")
