import fcntl
import os

from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.paths import container_rootfs


def _get_session_file_and_lock(name: str):
    data_dir = os.path.join(RUNTIME_DIR, "data", name)
    os.makedirs(data_dir, exist_ok=True)
    session_file = os.path.join(data_dir, "sessions")
    lock_file = os.path.join(data_dir, "sessions.lock")
    return session_file, lock_file


def get_active_chroot_pids(name: str) -> list[int]:
    """Return a list of host PIDs of processes currently running inside the container's chroot.

    Inspects /proc/*/root to identify chrooted processes.
    """
    rootfs = container_rootfs(name)
    rootfs_abs = os.path.realpath(rootfs)
    pids = []

    if not os.path.exists("/proc"):
        return []

    my_pid = os.getpid()
    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            if pid == my_pid:
                continue
            try:
                # Resolve the root symlink of the process
                root_link = os.path.realpath(f"/proc/{pid}/root")
                if root_link == rootfs_abs:
                    pids.append(pid)
            except (OSError, PermissionError):
                pass
    except OSError:
        pass
    return pids


def increment(name: str) -> int:
    """Increment the active sessions count for a container and return the new count.

    Uses file locking to ensure safety across concurrent updates.
    """
    session_file, lock_file = _get_session_file_and_lock(name)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        count_val = 0
        if os.path.exists(session_file):
            try:
                with open(session_file) as f:
                    count_val = int(f.read().strip() or 0)
            except (ValueError, OSError):
                count_val = 0

        # Self-heal check: If process list is empty, count must be 0
        if count_val > 0 and not get_active_chroot_pids(name):
            count_val = 0

        count_val += 1
        with open(session_file, "w") as f:
            f.write(str(count_val))

        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return count_val


def decrement(name: str) -> int:
    """Decrement the active sessions count for a container and return the new count.

    Uses file locking to ensure safety.
    """
    session_file, lock_file = _get_session_file_and_lock(name)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        count_val = 0
        if os.path.exists(session_file):
            try:
                with open(session_file) as f:
                    count_val = int(f.read().strip() or 0)
            except (ValueError, OSError):
                count_val = 0

        # Self-heal check: If process list is empty, count must be 0
        active_pids = get_active_chroot_pids(name)
        count_val = 0 if not active_pids else max(0, count_val - 1)

        with open(session_file, "w") as f:
            f.write(str(count_val))

        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return count_val


def count(name: str) -> int:
    """Return the current session count, adjusting for dead sessions (self-healing)."""
    session_file, lock_file = _get_session_file_and_lock(name)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        count_val = 0
        if os.path.exists(session_file):
            try:
                with open(session_file) as f:
                    count_val = int(f.read().strip() or 0)
            except (ValueError, OSError):
                count_val = 0

        # Self-heal check: If process list is empty, count must be 0
        if count_val > 0 and not get_active_chroot_pids(name):
            count_val = 0
            with open(session_file, "w") as f:
                f.write("0")

        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return count_val
