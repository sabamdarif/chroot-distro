"""Per-session registry for the ``ps`` command.

Architecture: Each ``login`` or ``run`` session writes a JSON file under
``SESSIONS_DIR/<pid>.json`` and holds an exclusive ``flock(2)`` on it for
the lifetime of the session.  The ``ps`` command probes liveness with a
shared, non-blocking flock: refusal means the session is alive; success
means it is dead (the file is pruned on sight).

For interactive sessions (``subprocess.run`` in the parent), the parent
holds the flock fd open during the wait and closes it in the ``finally``
block.  For detached sessions (``subprocess.Popen`` with
``start_new_session``), the fd is passed to the child via ``pass_fds``
so the lock survives the parent's exit.

Registration is strictly best-effort: any failure returns ``None`` and
must never prevent a session from starting.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time

from chroot_distro.constants import SESSIONS_DIR


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

    Best-effort: every failure path returns ``None`` and is silently ignored.
    """
    try:
        os.makedirs(SESSIONS_DIR, exist_ok=True)
    except OSError:
        return None

    pid = os.getpid()
    final_path = os.path.join(SESSIONS_DIR, f"{pid}.json")
    tmp_path = os.path.join(SESSIONS_DIR, f".{pid}.{os.urandom(4).hex()}.tmp")

    payload = {
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

    try:
        fd = open(tmp_path, "w")  # noqa: SIM115
    except OSError:
        return None

    # Clear O_CLOEXEC so the fd (and its flock) can be inherited by child
    # processes when passed via pass_fds for detached sessions.
    with contextlib.suppress(OSError):
        os.set_inheritable(fd.fileno(), True)

    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        _safe_close(fd)
        _safe_unlink(tmp_path)
        return None

    try:
        json.dump(payload, fd)
        fd.write("\n")
        fd.flush()
    except OSError:
        _safe_close(fd)
        _safe_unlink(tmp_path)
        return None

    # Atomic publish: flock lives on the open file description (inode),
    # not the path, so the rename preserves the lock.
    try:
        os.replace(tmp_path, final_path)
    except OSError:
        _safe_close(fd)
        _safe_unlink(tmp_path)
        return None

    return _SessionHandle(fd)


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
        _safe_close(self._fd)
        self._fd = None


def active_sessions() -> list[dict]:
    """Return a list of live session records, pruning dead ones.

    Each record is the dict written by :func:`register_session`.  Files whose
    holder has exited are unlinked as a side effect.  Results are sorted by
    start time then PID.
    """
    try:
        names = os.listdir(SESSIONS_DIR)
    except OSError:
        return []

    sessions: list[dict] = []
    for name in names:
        if name.startswith(".") or not name.endswith(".json"):
            continue
        path = os.path.join(SESSIONS_DIR, name)

        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = None

        if not _session_alive(path):
            _safe_unlink(path)
            continue

        if isinstance(data, dict):
            sessions.append(data)

    sessions.sort(key=lambda s: (s.get("start_time", 0.0), s.get("pid", 0)))
    return sessions


def _session_alive(path: str) -> bool:
    """Return True iff a process still holds the exclusive lock on *path*.

    Probes with a shared, non-blocking flock: refusal means the session's
    exclusive lock is still held (alive); success means the file is unheld
    (the session is dead).
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            # EACCES/EAGAIN means the exclusive lock is held → alive.
            return True
        # Acquired the shared lock: nobody holds it → dead.
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _safe_close(fd) -> None:
    with contextlib.suppress(OSError):
        fd.close()


def _safe_unlink(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


def resolve_container_by_pid(pid: int) -> str | None:
    """Return the container name for a live session with the given PID, or ``None``.

    Iterates the active session registry (the same data ``ps`` displays)
    and returns the ``container`` field of the matching entry.  Only PIDs
    that appear in the registry are accepted, so arbitrary host PIDs can
    never be resolved to a container.
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
    except Exception:
        return result
    for name in names:
        pids = get_active_chroot_pids(name)
        if pids:
            result[name] = pids
    return result


__all__ = ("active_sessions", "containers_with_active_pids", "register_session", "resolve_container_by_pid")
