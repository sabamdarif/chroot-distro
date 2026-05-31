import contextlib
import os
import signal
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
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

    with ContainerLock(container_name, exclusive=True, command="unmount"):
        # 1. Get active sessions/processes
        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            log_info(f"Stopping active sessions/processes in container '{container_name}' (PIDs: {active_pids})...")

            # Send SIGTERM to all active chroot processes
            for pid in active_pids:
                log_info(f"Sending SIGTERM to process {pid}...")
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)

            # Wait up to 2 seconds for processes to terminate
            start_time = time.time()
            while time.time() - start_time < 2.0:
                remaining_pids = session.get_active_chroot_pids(container_name)
                if not remaining_pids:
                    break
                time.sleep(0.1)

            # Check if any remaining PIDs, send SIGKILL
            remaining_pids = session.get_active_chroot_pids(container_name)
            if remaining_pids:
                log_info(f"Processes {remaining_pids} did not exit. Sending SIGKILL...")
                for pid in remaining_pids:
                    with contextlib.suppress(OSError):
                        os.kill(pid, signal.SIGKILL)

                # Wait up to 1 second for SIGKILL to take effect
                start_time = time.time()
                while time.time() - start_time < 1.0:
                    remaining_pids = session.get_active_chroot_pids(container_name)
                    if not remaining_pids:
                        break
                    time.sleep(0.1)

                remaining_pids = session.get_active_chroot_pids(container_name)
                if remaining_pids:
                    warn(f"Some processes could not be stopped: {remaining_pids}")

        # 2. Reset session count to 0
        log_info(f"Setting active sessions count for '{container_name}' to 0.")
        session.reset(container_name)

        holder = namespace.get_live_holder(container_name)

        # 3. Unmount all nested mounts under rootfs
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

        remaining_mounts = mount_manager.get_active_mounts(rootfs_dir)
        if remaining_mounts:
            warn(f"Some active mounts remain: {remaining_mounts}")
        else:
            log_info(f"Container '{container_name}' successfully unmounted.")
