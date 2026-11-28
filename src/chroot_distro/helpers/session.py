# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Per-container session refcount, so the last session out tears the mounts down.

`data/<name>/sessions` holds one integer, guarded by `sessions.lock`. `login` and
`run` increment on the way in and decrement on the way out; the mounts and the
namespace holder are only released when the count reaches zero, which is what lets
several sessions share one set of mounts.

A counter cannot survive a crash alone, so `/proc` is the authority and the file
is a cache of it. `get_active_chroot_pids` scans `/proc/*/root` for processes whose
root is this rootfs. Increment and count discard a positive count when no such
process exists; increment also clears stale mount options. Decrement writes zero
when no processes remain, otherwise it subtracts one without going below zero.

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

`lock` pins the state directory through the guarded platform-anchor walk and
yields that directory fd, not the flock fd. Callers pass it as `state_fd` to keep
reads, atomic replacements and deletion under the same pin. The lock inode is
never written or replaced. Standalone options operations pin their own directory
and remain best-effort. Counter and lock I/O failures stop the operation.

These guards confine I/O; they do not authenticate regular state files or prevent
a guest from replacing a valid lock name. `helpers/session_registry.py` owns the
per-session JSON files used by `ps` and `kill`.
"""

import contextlib
import fcntl
import json
import logging
import os
import typing

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.paths import container_rootfs, open_container_data_dir

log = logging.getLogger(__name__)


_COUNTER_LIMIT = 64
_MOUNT_OPTIONS_LIMIT = 1024 * 1024


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


def _state_error(name: str, exc: OSError) -> ChrootDistroError:
    return ChrootDistroError(f"cannot access session state for '{name}': {exc}")


@contextlib.contextmanager
def lock(name: str) -> typing.Iterator[int]:
    """Acquire the session lock and yield its pinned state-directory fd."""
    with contextlib.ExitStack() as stack:
        try:
            state_fd = open_container_data_dir(name, create=True)
            stack.callback(os.close, state_fd)
            lock_fd, _ = dirfd.open_regular_at(state_fd, "sessions.lock", os.O_RDWR | os.O_CREAT, 0o600)
            stack.callback(os.close, lock_fd)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise _state_error(name, exc) from exc
        try:
            yield state_fd
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                raise _state_error(name, exc) from exc


def _read_count(name: str, state_fd: int) -> int:
    try:
        fd, _ = dirfd.open_regular_at(state_fd, "sessions", os.O_RDONLY)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(_COUNTER_LIMIT + 1)
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise _state_error(name, exc) from exc
    if len(data) > _COUNTER_LIMIT:
        return 0
    try:
        return max(0, int(data.strip() or b"0"))
    except ValueError:
        return 0


def _write_count(name: str, state_fd: int, value: int) -> None:
    try:
        with atomic_write("sessions", dir_fd=state_fd) as fh:
            fh.write(str(value))
    except OSError as exc:
        raise _state_error(name, exc) from exc


def increment(name: str, state_fd: int | None = None) -> int:
    """Increment under the supplied lock's directory pin, or acquire a lock."""
    if state_fd is None:
        with lock(name) as state_fd:
            return increment(name, state_fd=state_fd)
    count_val = _read_count(name, state_fd)
    if count_val > 0 and not get_active_chroot_pids(name):
        count_val = 0
        clear_mount_options(name, state_fd=state_fd)
    count_val += 1
    _write_count(name, state_fd, count_val)
    return count_val


def decrement(name: str, state_fd: int | None = None) -> int:
    """Decrement under the supplied lock's directory pin, or acquire a lock."""
    if state_fd is None:
        with lock(name) as state_fd:
            return decrement(name, state_fd=state_fd)
    count_val = _read_count(name, state_fd)
    count_val = max(0, count_val - 1) if get_active_chroot_pids(name) else 0
    _write_count(name, state_fd, count_val)
    return count_val


def count(name: str) -> int:
    """Return the current session count, adjusting for dead sessions."""
    with lock(name) as state_fd:
        count_val = _read_count(name, state_fd)
        if count_val > 0 and not get_active_chroot_pids(name):
            count_val = 0
            _write_count(name, state_fd, 0)
        return count_val


def reset(name: str) -> None:
    """Reset the active session count under the session lock."""
    with lock(name) as state_fd:
        _write_count(name, state_fd, 0)


@contextlib.contextmanager
def _state_dir(name: str, state_fd: int | None) -> typing.Iterator[int]:
    if state_fd is not None:
        yield state_fd
        return
    fd = open_container_data_dir(name, create=True)
    try:
        yield fd
    finally:
        os.close(fd)


def save_mount_options(name: str, opts: dict, *, state_fd: int | None = None) -> None:
    """Persist the mount options applied by the latest session."""
    payload = json.dumps(opts)
    if len(payload) > _MOUNT_OPTIONS_LIMIT:
        log.debug("Mount options for '%s' exceed the state size limit", name)
        return
    try:
        with _state_dir(name, state_fd) as fd, atomic_write("mount_opts.json", dir_fd=fd) as fh:
            fh.write(payload)
    except OSError as exc:
        log.debug("Failed to save mount options for '%s': %s", name, exc)


def load_mount_options(name: str, *, state_fd: int | None = None) -> dict[str, object] | None:
    """Load bounded regular-file mount options, or return ``None``."""
    try:
        with _state_dir(name, state_fd) as fd:
            file_fd, _ = dirfd.open_regular_at(fd, "mount_opts.json", os.O_RDONLY)
            with os.fdopen(file_fd, "rb") as fh:
                payload = fh.read(_MOUNT_OPTIONS_LIMIT + 1)
        if len(payload) > _MOUNT_OPTIONS_LIMIT:
            return None
        data = json.loads(payload)
        return dict(data) if isinstance(data, dict) else None
    except (OSError, ValueError, RecursionError):
        return None


def live_mount_options(name: str) -> dict[str, object] | None:
    """Return the saved options of a container that has a session running now.

    ``None`` when nothing is chrooted into the rootfs: the record is then stale,
    :func:`increment` is about to clear it, and the mounts it describes
    are gone or about to be, so adopting it would ask for mounts nobody holds.
    """
    if not get_active_chroot_pids(name):
        return None
    return load_mount_options(name)


def clear_mount_options(name: str, *, state_fd: int | None = None) -> None:
    """Remove mount options relative to the held or newly opened state pin."""
    with contextlib.suppress(OSError), _state_dir(name, state_fd) as fd:
        os.unlink("mount_opts.json", dir_fd=fd)
