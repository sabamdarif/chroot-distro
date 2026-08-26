# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Per-container session refcount, so the last session out tears the mounts down.

`data/<name>/sessions` holds one integer, guarded by `sessions.lock`. `login` and
`run` increment on the way in and decrement on the way out; the mounts and the
namespace holder are only released when the count reaches zero, which is what lets
several sessions share one set of mounts.

A counter that only ever goes up and down cannot survive a crash, so `/proc` is the
real authority and the file is a cache of it. Every read path calls
`get_active_chroot_pids`, which scans `/proc/*/root` for processes whose root really
is this rootfs, and a positive count with no such process is corrected to zero on the
spot, along with the stale `mount_opts.json` a crashed session left behind. This is
why `decrement` can return zero from any starting value: what it writes is what the
kernel says, not one less than what the file said.

`has_tracked_ancestor` exists because a process inside the container is not always
chrooted itself. A browser helper a login spawned is a descendant of a tracked pid, so
the /proc parent chain is walked up to init before anything is called an orphan.

`mount_opts.json` records the options the container is running with: the `--bind`
specs, the `--shared-*` flags and the `--env` values a later session adopts through
`live_mount_options`, so joining a live container gives the same view of it instead
of a warning that a flag was ignored. Every session rewrites it with the union it
applied, and it is removed on the last teardown or by the self-heal above. Only a
record with a live process behind it may be adopted, which is what
`live_mount_options` checks: a crashed session's record describes mounts that are
about to be torn down and rebuilt.

Session *identity* is not here: `helpers/session_registry.py` owns the per-session
JSON files `ps` and `kill` work from. This file only counts.
"""

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


def read_ppid(pid: int) -> int | None:
    """Return the parent PID of *pid* from ``/proc/<pid>/stat``, or ``None``.

    The process name in field 2 can contain spaces and parentheses, so we
    split after the final ``)``: everything past it is space-separated and
    the second field there is the PPID.
    """
    try:
        with open(f"/proc/{pid}/stat") as fh:
            stat = fh.read()
        rpar = stat.rfind(")")
        if rpar == -1:
            return None
        fields = stat[rpar + 2 :].split()
        return int(fields[1])
    except (OSError, ValueError, IndexError):
        return None


def has_tracked_ancestor(pid: int, tracked_pids: set[int]) -> bool:
    """Return True if *pid* itself or any of its ancestors is in *tracked_pids*.

    Walks the ``/proc`` parent chain up to init (PID 1), so descendants of a
    tracked session (e.g. the browser helpers a login spawns) are recognised
    as belonging to that session rather than mistaken for orphans.
    """
    seen: set[int] = set()
    current: int | None = pid
    while current and current > 1 and current not in seen:
        if current in tracked_pids:
            return True
        seen.add(current)
        current = read_ppid(current)
    return False


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

    if count_val > 0 and not get_active_chroot_pids(name):
        count_val = 0
        # Stale mount_opts.json from a crashed session.
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


def live_mount_options(name: str) -> dict[str, object] | None:
    """Return the saved options of a container that has a session running now.

    ``None`` when nothing is chrooted into the rootfs: the record is then stale,
    :func:`_increment_inner` is about to clear it, and the mounts it describes
    are gone or about to be, so adopting it would ask for mounts nobody holds.
    """
    if not get_active_chroot_pids(name):
        return None
    return load_mount_options(name)


def clear_mount_options(name: str) -> None:
    """Remove the persisted mount options file (last session teardown / self-heal)."""
    path = _mount_opts_file(name)
    with contextlib.suppress(OSError):
        os.unlink(path)
