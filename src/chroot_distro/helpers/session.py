import contextlib
import fcntl
import json
import logging
import os
import typing

from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.paths import container_rootfs

log = logging.getLogger(__name__)


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
            except (OSError, PermissionError) as exc:
                log.debug("Failed to read root link of process %s: %s", pid, exc)
    except OSError as exc:
        log.warning("Failed to list /proc: %s", exc)
    return pids


@contextlib.contextmanager
def lock(name: str) -> typing.Iterator[typing.TextIO]:
    """Acquire the session lock for a container."""
    _, lock_file = _get_session_file_and_lock(name)
    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            yield lock_fh
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _increment_inner(name: str, session_file: str) -> int:
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
        # Stale mount_opts.json from a crashed session — clean it up.
        clear_mount_options(name)

    count_val += 1
    with open(session_file, "w") as f:
        f.write(str(count_val))

    return count_val


def increment(name: str, lock_fh: typing.IO | None = None) -> int:
    """Increment the active sessions count for a container and return the new count.

    Uses file locking to ensure safety across concurrent updates.
    """
    session_file, lock_file = _get_session_file_and_lock(name)

    if lock_fh is not None:
        return _increment_inner(name, session_file)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        res = _increment_inner(name, session_file)
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return res


def _decrement_inner(name: str, session_file: str) -> int:
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

    return count_val


def decrement(name: str, lock_fh: typing.IO | None = None) -> int:
    """Decrement the active sessions count for a container and return the new count.

    Uses file locking to ensure safety.
    """
    session_file, lock_file = _get_session_file_and_lock(name)

    if lock_fh is not None:
        return _decrement_inner(name, session_file)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        res = _decrement_inner(name, session_file)
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        return res


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


def reset(name: str) -> None:
    """Reset the active sessions count for a container to 0.

    Uses file locking to ensure safety.
    """
    session_file, lock_file = _get_session_file_and_lock(name)

    with open(lock_file, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        with open(session_file, "w") as f:
            f.write("0")
        fcntl.flock(lock_fh, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Mount options metadata
# ---------------------------------------------------------------------------


def _mount_opts_file(name: str) -> str:
    data_dir = os.path.join(RUNTIME_DIR, "data", name)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "mount_opts.json")


def save_mount_options(name: str, opts: dict) -> None:
    """Persist the mount options used by the first session.

    Called once when ``sess_count == 1`` so that subsequent sessions can
    compare their own options against the running configuration.
    """
    path = _mount_opts_file(name)
    try:
        with open(path, "w") as fh:
            json.dump(opts, fh)
    except OSError as exc:
        log.debug("Failed to save mount options for '%s': %s", name, exc)


def load_mount_options(name: str) -> dict[str, object] | None:
    """Load the mount options saved by the first session, or ``None``."""
    path = _mount_opts_file(name)
    try:
        with open(path) as fh:
            data = json.load(fh)
        return dict(data) if isinstance(data, dict) else None
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def clear_mount_options(name: str) -> None:
    """Remove the persisted mount options file (last session teardown / self-heal)."""
    path = _mount_opts_file(name)
    with contextlib.suppress(OSError):
        os.unlink(path)
