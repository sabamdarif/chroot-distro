import os
import sys

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_error, log_info
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_rootfs


def command_rename(args) -> None:
    """Rename a container directory."""
    orig = args.orig_name
    new = args.new_name

    if orig == new:
        crit_error("original and new names must differ.")
        sys.exit(1)

    require_valid_name(orig)
    require_valid_name(new)

    orig_dir = container_dir(orig)
    new_dir = container_dir(new)
    orig_rootfs = container_rootfs(orig)

    if not os.path.isdir(orig_rootfs):
        crit_error(f"container '{orig}' is not installed.")
        sys.exit(1)

    if os.path.isdir(new_dir):
        crit_error(f"container '{new}' already exists.")
        sys.exit(1)

    first, second = (orig, new) if orig < new else (new, orig)
    with (
        ContainerLock(first, exclusive=True, command="rename"),
        ContainerLock(second, exclusive=True, command="rename"),
    ):
        # 1. Active sessions check on orig
            active_pids = session.get_active_chroot_pids(orig)
            if active_pids:
                crit_error(f"Cannot rename container '{orig}': It has active sessions (PIDs: {active_pids}).")
                sys.exit(1)

            # 2. Mount check on orig
            try:
                mount_manager.ensure_no_mounts(orig_rootfs)
            except Exception as e:
                crit_error(f"Failed mount safety check: {e}")
                sys.exit(1)

            log_info(f"Renaming '{orig}' to '{new}'...")
            try:
                os.rename(orig_dir, new_dir)
            except OSError as exc:
                log_error(f"Failed to rename container: {exc}")
                sys.exit(1)

            log_info("Finished renaming the container.")
