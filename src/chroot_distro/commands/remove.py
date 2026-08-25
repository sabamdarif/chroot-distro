# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro remove`: stop the container, unmount it, delete both its trees.

Two trees go, not one: `containers/<name>/` and the per-container runtime state
under `data/<name>/`. The lock file is unlinked only after the `ContainerLock`
context has exited, since dropping it while the flock is still held would leave the
next caller locking a file no one else can reach.

Sessions end the way `unmount` ends them, SIGTERM and then SIGKILL after a grace
period, and a container with a process or a mount still standing afterwards is
refused rather than deleted from under it.

`_remove_path` chmods as it descends, because a rootfs is guest content and a
directory left mode 000 is otherwise undeletable, and it reports every entry it
removed so `--verbose` and the count bar have something to show. `_count_files`
pre-walks only when that bar will be drawn. `commands/reset.py` reuses
`_remove_path` for the rootfs alone.
"""

import contextlib
import os
import signal
import stat
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.locking import ContainerLock, container_lock_path
from chroot_distro.message import crit_error, log_error, log_info
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_rootfs


def _remove_path(path: str, on_remove=None) -> bool:
    """Remove path recursively, fixing permissions on the fly."""
    try:
        st = os.lstat(path)
    except OSError:
        return True

    if not stat.S_ISDIR(st.st_mode):
        if not stat.S_ISLNK(st.st_mode):
            needed = stat.S_IRUSR | stat.S_IWUSR
            if (st.st_mode & needed) != needed:
                with contextlib.suppress(OSError):
                    os.chmod(path, st.st_mode | needed)
        try:
            os.unlink(path)
            if on_remove:
                on_remove(path)
            return True
        except OSError:
            return False

    needed = stat.S_IRWXU
    if (st.st_mode & needed) != needed:
        try:
            os.chmod(path, st.st_mode | needed)
        except OSError:
            return False

    ok = True
    try:
        entries = os.listdir(path)
    except OSError:
        return False

    for name in entries:
        if not _remove_path(os.path.join(path, name), on_remove):
            ok = False

    if ok:
        try:
            os.rmdir(path)
            if on_remove:
                on_remove(path)
        except OSError:
            ok = False

    return ok


def _count_files(path: str) -> int:
    """Count all directory and file entries recursively under *path*."""
    count = 0
    try:
        count += 1
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        count += _count_files(entry.path)
                    else:
                        count += 1
                except OSError:
                    count += 1
    except OSError:
        return 1
    return count


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

    with ContainerLock(container_name, exclusive=True, command="remove"):
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

        log_info(f"Removing container '{container_name}'...")

        from collections.abc import Callable

        from chroot_distro.progress import clear_bar, draw_count_bar, progress_active

        show_progress = progress_active() and not verbose
        total_files = 0
        if show_progress:
            container_path = container_dir(container_name)
            if os.path.isdir(container_path):
                total_files += _count_files(container_path)
            data_dir = os.path.join(RUNTIME_DIR, "data", container_name)
            if os.path.isdir(data_dir):
                total_files += _count_files(data_dir)

        removed_count = 0

        on_remove: Callable[[str], None] | None = None
        if verbose or show_progress:

            def _on_remove(path: str) -> None:
                nonlocal removed_count
                removed_count += 1
                if verbose:
                    log_info(f"Removed: '{path}'")
                elif show_progress:
                    draw_count_bar(removed_count, total_files, label="Removing", unit="files")

            on_remove = _on_remove

        try:
            if not _remove_path(container_dir(container_name), on_remove):
                log_error("Finished with errors. Some files probably were not deleted.")
                sys.exit(1)

            data_dir = os.path.join(RUNTIME_DIR, "data", container_name)
            if os.path.isdir(data_dir):
                _remove_path(data_dir, on_remove)
        finally:
            if show_progress:
                clear_bar()

    # The ContainerLock context has now exited and the flock is released;
    # it is safe to delete the lock file itself.
    with contextlib.suppress(OSError):
        os.unlink(container_lock_path(container_name))

    log_info("Finished removing the container.")
