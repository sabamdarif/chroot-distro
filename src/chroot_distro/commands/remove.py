import contextlib
import os
import stat
import sys

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.locking import ContainerLock
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


def command_remove(args) -> None:
    """Delete an installed container's directory tree."""
    container_name = args.container_name
    verbose = getattr(args, "verbose", False)

    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)

    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    with ContainerLock(container_name, exclusive=True, command="remove"):
        # 1. Active sessions safety check
        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            crit_error(f"Cannot remove container '{container_name}': It has active sessions (PIDs: {active_pids}).")
            sys.exit(1)

        # 2. Mount safety check: check and unmount all active mounts nested under rootfs
        try:
            mount_manager.ensure_no_mounts(rootfs_dir)
        except Exception as e:
            crit_error(f"Failed mount safety check: {e}")
            sys.exit(1)

        log_info(f"Removing container '{container_name}'...")

        on_remove = None
        if verbose:
            def on_remove(path):
                log_info(f"Removed: '{path}'")

        if not _remove_path(container_dir(container_name), on_remove):
            log_error("Finished with errors. Some files probably were not deleted.")
            sys.exit(1)

    log_info("Finished removing the container.")
