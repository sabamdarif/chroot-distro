# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""One atomically published, flock-held record per login or run session.

All registry operations retain a directory descriptor from the platform anchor.
Registration locks an exclusive temporary and keeps a duplicate descriptor alive
after publication. The returned handle owns that duplicate; callers retain it
until exit or pass it through `spawn_detached`'s `keep_fds`. Closing the parent
copy must not explicitly unlock the child's shared open file description.

Records are limited to 1 MiB and published with mode 0644 so Termux's unelevated
`ps` can read them. Readers probe and read the same regular-file descriptor and
prune unlocked entries relative to the pinned directory. Registration I/O failures
are logged and return None; interrupts propagate after descriptor cleanup.

A flock proves only that the opened inode is locked. These filesystem guards do
not authenticate record fields, the recorded PID or its container membership.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import logging
import os
import time

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.paths import open_sessions_dir

log = logging.getLogger(__name__)

_RECORD_LIMIT = 1024 * 1024


def register_session(
    *,
    container: str,
    kind: str,
    command_argv: list[str],
    user: str,
    isolated: bool = False,
    minimal: bool = False,
    detached: bool = False,
) -> _SessionHandle | None:
    """Record a session and return a handle that keeps it alive, or ``None``.

    The caller must keep the returned handle referenced (not garbage-collected)
    for the lifetime of the session.  Call ``handle.close()`` when the session
    ends, or pass ``handle.fileno()`` to ``pass_fds`` so a detached child
    inherits the lock.

    I/O failures or oversized records return ``None`` and are logged.
    """
    pid = os.getpid()
    record = {
        "pid": pid,
        "container": container,
        "kind": kind,
        "command": list(command_argv),
        "user": user,
        "start_time": time.time(),
        "isolated": bool(isolated),
        "minimal": bool(minimal),
        "detached": bool(detached),
    }
    payload = json.dumps(record, ensure_ascii=True) + "\n"
    if len(payload) > _RECORD_LIMIT:
        log.warning("Session record for PID %s exceeds the size limit", pid)
        return None

    directory_fd = None
    retained = None
    try:
        directory_fd = open_sessions_dir(create=True)
        with atomic_write(f"{pid}.json", dir_fd=directory_fd, mode=0o644) as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            duplicate = os.dup(fh.fileno())
            try:
                retained = os.fdopen(duplicate, "w")
            except BaseException:
                os.close(duplicate)
                raise
            os.set_inheritable(retained.fileno(), True)
            fh.write(payload)
        handle = _SessionHandle(retained)
        retained = None
        return handle
    except OSError as exc:
        log.warning("Failed to register session for PID %s: %s", pid, exc)
        return None
    finally:
        if retained is not None:
            _safe_close(retained)
        if directory_fd is not None:
            with contextlib.suppress(OSError):
                os.close(directory_fd)


class _SessionHandle:
    """Opaque handle that holds the flock for one session."""

    __slots__ = ("_fd",)

    def __init__(self, fd) -> None:
        self._fd = fd

    def fileno(self) -> int:
        """Return the underlying file descriptor number (for ``pass_fds``)."""
        if self._fd is None:
            raise ValueError("I/O operation on closed file.")
        return int(self._fd.fileno())

    def close(self) -> None:
        """Release the lock and close the file descriptor."""
        if self._fd is not None:
            _safe_close(self._fd)
            self._fd = None


def active_sessions() -> list[dict]:
    """Return a list of live session records, pruning dead ones.

    Each record is the dict written by :func:`register_session`.  Files whose
    holder has exited are unlinked as a side effect.  Results are sorted by
    start time then PID.
    """
    directory_fd = None
    try:
        directory_fd = open_sessions_dir()
        sessions = [
            data
            for name in os.listdir(directory_fd)
            if not name.startswith(".") and name.endswith(".json")
            if (data := _read_session(directory_fd, name)) is not None
        ]
    except OSError:
        return []
    finally:
        if directory_fd is not None:
            with contextlib.suppress(OSError):
                os.close(directory_fd)
    sessions.sort(key=lambda s: (s.get("start_time", 0.0), s.get("pid", 0)))
    return sessions


def _read_session(directory_fd: int, name: str) -> dict | None:
    """Read a locked record, or prune an unlocked inode that still has its name."""
    fd = None
    try:
        fd, original = dirfd.open_regular_at(directory_fd, name, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                return None
        else:
            if os.path.samestat(original, dirfd.lstat_at(directory_fd, name)):
                os.unlink(name, dir_fd=directory_fd)
            return None
        with open(fd, "rb", closefd=False) as fh:
            payload = fh.read(_RECORD_LIMIT + 1)
        if len(payload) > _RECORD_LIMIT:
            return None
        data = json.loads(payload)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _safe_close(fd) -> None:
    with contextlib.suppress(OSError):
        fd.close()


def resolve_container_by_pid(pid: int) -> str | None:
    """Return the container name for a live session with the given PID, or ``None``.

    Iterates the active session registry (the same data ``ps`` displays)
    and returns the ``container`` field of the matching entry.  Only PIDs
    that appear in a locked registry record are accepted. Record fields are
    advisory and do not authenticate the process's container membership.
    """
    for sess in active_sessions():
        if sess.get("pid") == pid:
            return sess.get("container")
    return None


def containers_with_active_pids() -> dict[str, list[int]]:
    """Return ``{container_name: [pid, ...]}`` for every installed container
    that has at least one process chrooted into its rootfs.

    This is the ``/proc/*/root`` fallback used by ``ps`` to detect
    orphaned processes that are no longer tracked by the flock-based
    session registry (e.g. when the parent chroot-distro process crashed).
    """
    from chroot_distro.helpers.session import get_active_chroot_pids
    from chroot_distro.paths import installed_containers

    result: dict[str, list[int]] = {}
    try:
        names = installed_containers()
    except Exception as exc:
        log.warning("Failed to list installed containers: %s", exc)
        return result
    for name in names:
        pids = get_active_chroot_pids(name)
        if pids:
            result[name] = pids
    return result


__all__ = ("active_sessions", "containers_with_active_pids", "register_session", "resolve_container_by_pid")
