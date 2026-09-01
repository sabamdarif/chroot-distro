# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro unmount`: end a container's sessions and drop its mounts.

The exclusive `ContainerLock` is waited for rather than forced, which is the whole
difference from `kill`: this is the orderly path, and a caller who cannot wait wants
that command instead. Inside the lock the order is fixed: SIGTERM the chrooted
processes, SIGKILL whatever outlives the grace period, zero the session count, then
unmount.

`mount_manager.unmount_all` does the unmounting, through the holder when one is
alive, because a mount made inside its namespace cannot be seen from here. The
holder and the isolation mode are released after it, never while a mount still
depends on them. On Termux a deep sweep follows, for the mounts an earlier
`su --mount-master` left in another namespace.
"""

import contextlib
import os
import signal
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.constants import IS_TERMUX
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_info, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_rootfs


def command_unmount(args) -> None:
    """Safely unmount a container's filesystem bindings after stopping active sessions."""
    container_name = args.container_name
    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    failed = False

    with ContainerLock(container_name, exclusive=True, command="unmount"):
        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            log_info(f"Stopping active sessions/processes in container '{container_name}' (PIDs: {active_pids})...")

            for pid in active_pids:
                log_info(f"Sending SIGTERM to process {pid}...")
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

                remaining_pids = session.get_active_chroot_pids(container_name)
                if remaining_pids:
                    warn(f"Some processes could not be stopped: {remaining_pids}")
                    failed = True

        log_info(f"Setting active sessions count for '{container_name}' to 0.")
        session.reset(container_name)
        session.clear_mount_options(container_name)

        holder = namespace.get_live_holder(container_name)

        log_info("Unmounting active mount points under rootfs...")
        try:
            mount_manager.unmount_all(rootfs_dir, holder=holder)
        except Exception as e:
            crit_error(f"Failed to unmount: {e}")
            sys.exit(1)

        if holder is not None:
            namespace.release_holder(container_name)
            namespace.clear_isolation_mode(container_name)
            holder = None

        # Termux: mounts made by an earlier `su --mount-master` live in the
        # global namespace and reach this process as slave copies that cannot
        # be unmounted locally, so they go at the source and propagate.
        if IS_TERMUX:
            log_info("Cleaning stale container mounts in other mount namespaces...")
            mount_manager.deep_clean_container_mounts(container_name)

        remaining_mounts = mount_manager.get_active_mounts(rootfs_dir)
        if remaining_mounts:
            warn(f"Some active mounts remain: {remaining_mounts}")
            failed = True
        else:
            log_info(f"Container '{container_name}' successfully unmounted.")

    if failed:
        sys.exit(1)
