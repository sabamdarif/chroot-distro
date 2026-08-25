# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Advisory flock(2) locks that serialise commands against each other.

Three namespaces, one class each: `ContainerLock` per container name,
`BuildLock` per (image_ref, arch) pair hashed to a short key, `RunCacheLock` per
build-cache key. Their files live under `locks/`, `locks/build/` and
`locks/run-cache/` below RUNTIME_DIR. The first line of a lock file is
`PID command`, which is what lets a conflict name the process holding it; it is
written only once the flock is actually ours, since the file is opened O_CREAT
without O_TRUNC and truncating earlier would wipe the holder's own line before
the attempt that fails. Exclusive locks are re-entrant within one process, keyed
by lock path in `_held_exclusive`.

`locks/` is guest-writable on Termux (RUNTIME_DIR sits under the prefix bound
read-write into every non-isolated container) and every name in it is
predictable, so no lock file is ever addressed by path: the directories are
descended O_NOFOLLOW one level at a time and the file is opened as
`(dir_fd, name)` with a plain-file check. Nothing but this program writes there,
so an entry that is not a plain file was planted, and it is dropped and the real
lock made in its place. Following one instead would truncate the host file a
symlink names, or block forever on a FIFO with no writer.

Failing open or failing closed is decided per caller, and the difference is the
point of having both `_open_lock_file` and `open_lock_file_at`. An ordinary
refusal (read-only filesystem, no permission, a filesystem that ignores flock)
means "carry on without a lock", so a missing lock never stops the program from
running at all. A planted name that cannot be cleared is different: for a
container or build lock it raises `_HostileLockError` and `acquire()` returns
False, because passing it off as the ordinary case would leave every later
command unsynchronised. `open_lock_file_at` is the same opening rules with the
opposite policy, for the build-cache index's own lock, where losing the race
costs a concurrent `record()`'s entry rather than a torn file, since the index is
published through `atomic_write`.

Everything a caller sees about a holder (`busy_locks`, `holder_hint`) is a
cosmetic snapshot taken with a shared non-blocking probe. It is never consulted
to decide whether a lock is granted: `acquire()` alone decides that, and never
from a guess.
"""

import contextlib
import errno
import fcntl
import hashlib
import logging
import os
import typing

from chroot_distro import dirfd
from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.exceptions import LockConflictError

log = logging.getLogger(__name__)

LOCKS_DIR = os.path.join(RUNTIME_DIR, "locks")
_BUILD_LOCKS_DIR = os.path.join(LOCKS_DIR, "build")
_RUN_CACHE_LOCKS_DIR = os.path.join(LOCKS_DIR, "run-cache")

# The three lock directories as component lists below RUNTIME_DIR: what the
# O_NOFOLLOW walk descends, one level at a time.
_CONTAINER_PARTS = ("locks",)
_BUILD_PARTS = ("locks", "build")
_RUN_CACHE_PARTS = ("locks", "run-cache")

# Absolute lock-file paths for which this process currently holds an
# exclusive flock. Used to make exclusive locking re-entrant within a
# single invocation.
_held_exclusive: set[str] = set()


def container_lock_path(name: str) -> str:
    """Return the lock-file path for the container named *name*."""
    return os.path.join(LOCKS_DIR, f"{name}.lock")


def _build_lock_path(image_ref: str, arch: str) -> str:
    """Return the lock-file path for a build of (image_ref, arch)."""
    key = hashlib.sha256(f"{image_ref}_{arch}".encode()).hexdigest()[:16]
    return os.path.join(_BUILD_LOCKS_DIR, f"{key}.lock")


def container_busy_status(name: str) -> str:
    """Return a short container status for display (``idle`` or ``in use …``)."""
    hint = _hint_for(_CONTAINER_PARTS, f"{name}.lock")
    if hint:
        return f"in use{hint}"
    return "idle"


def _pid_state(pid: int) -> str:
    """Return the single-letter process state from /proc/<pid>/stat, or ''.

    'T' means stopped (job control, e.g. Ctrl+Z): the process still holds
    its flocks but will never release them until resumed or killed.
    """
    try:
        with open(f"/proc/{pid}/stat") as fh:
            stat = fh.read()
        # Field 3 follows the parenthesised comm, which may contain spaces.
        return stat.rpartition(")")[2].split()[0]
    except (OSError, IndexError):
        return ""


class _HostileLockError(Exception):
    """Raised when a lock file's name is occupied by something else."""


# What opening an existing entry that is not a plain file reports: ELOOP or
# ENOTDIR for a symlink (dirfd.is_refusal), EISDIR for a directory, EINVAL from
# open_regular_at()'s own type check, ENXIO for a FIFO with no reader.
_PLANTED_ERRNOS = frozenset((errno.EISDIR, errno.EINVAL, errno.ENXIO))


def _is_planted(exc: OSError) -> bool:
    """True when *exc* says the name is held by something not a plain file."""
    return dirfd.is_refusal(exc) or exc.errno in _PLANTED_ERRNOS


def _drop_planted(dir_fd: int, name: str) -> bool:
    """Remove whatever occupies *name* under dir_fd. True once the name is free.

    A directory needs rmdir and so only goes while it is empty, which is the one
    shape of this that can stay in the way. Everything else (a symlink, a FIFO,
    a socket, a device node) unlinks.
    """
    try:
        os.unlink(name, dir_fd=dir_fd)
        return True
    except FileNotFoundError:
        return True
    except OSError as exc:
        # unlink(2) on a directory is EISDIR on Linux, EPERM where POSIX leaves
        # the choice open.
        if exc.errno not in (errno.EISDIR, errno.EPERM):
            return False
    try:
        os.rmdir(name, dir_fd=dir_fd)
        return True
    except OSError:
        return False


def _open_lock_subdir(dir_fd: int, name: str, path: str) -> int | None:
    """Open (creating) the lock directory *name* under dir_fd. Descriptor, or None."""
    try:
        return dirfd.opendir_at(dir_fd, name)
    except FileNotFoundError:
        pass
    except OSError as exc:
        if not _is_planted(exc):
            return None
        if not _drop_planted(dir_fd, name):
            raise _HostileLockError(path) from None
    try:
        os.mkdir(name, 0o777, dir_fd=dir_fd)
    except FileExistsError:
        pass
    except OSError:
        return None
    try:
        return dirfd.opendir_at(dir_fd, name)
    except OSError as exc:
        if _is_planted(exc):
            raise _HostileLockError(path) from None
        return None


def _locks_dir_fd(parts: tuple[str, ...], create: bool = False) -> int | None:
    """Open one of the lock directories. Descriptor, or None.

    RUNTIME_DIR is the trust root, this program's own state directory named the
    way every other module names it, and every component below it is
    opened O_NOFOLLOW off the level above, so a `locks` (or `locks/build`)
    symlink a guest left behind sends nothing into a host directory. The root
    itself is still created by name: a first `install` on a machine that has
    never run this program must not proceed unlocked merely because RUNTIME_DIR
    does not exist yet.

    Creating descends level by level so a planted level gets the same treatment
    a planted lock file does: replaced, or refused. Reading (`busy_locks`, a
    holder hint) makes nothing and simply gives up.
    """
    if not create:
        return dirfd.opendir_under(RUNTIME_DIR, parts)

    fd: int | None = None
    try:
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        fd = dirfd.opendir(RUNTIME_DIR)
    except OSError:
        return None
    try:
        for depth, part in enumerate(parts, 1):
            nxt = _open_lock_subdir(fd, part, os.path.join(RUNTIME_DIR, *parts[:depth]))
            if nxt is None:
                return None
            os.close(fd)
            fd = nxt
        opened, fd = fd, None
        return opened
    finally:
        if fd is not None:
            os.close(fd)


def open_lock_file_at(dir_fd: int, name: str, path: str) -> int | None:
    """Open (creating) a lock file under dir_fd. Descriptor, or None.

    The public form of `_open_lock_file`, for a lock file this module does not
    own: the build-cache index keeps its own next to the index, which lives in
    the download cache rather than under RUNTIME_DIR/locks. The opening rules
    are the same; the *policy* differs at one point. Here a name that cannot be
    cleared comes back as None, "carry on without a lock", because that is
    already what the caller does on a filesystem that ignores flock and what it
    costs there is a concurrent `record()`'s entry, not a torn file, since the
    index itself is published through `atomic_write`. A container lock is the other
    way round and fails closed; see `acquire`.
    """
    try:
        return _open_lock_file(dir_fd, name, path)
    except _HostileLockError:
        return None


def _open_lock_file(dir_fd: int, name: str, path: str) -> int | None:
    """Open (creating) the lock file *name* under dir_fd. Descriptor, or None.

    O_NOFOLLOW plus open_regular_at()'s type check, so neither a symlink nor a
    FIFO standing under the name is opened: the first would have this program
    truncate the host file it points at, the second would block the command
    until a peer a hostile guest never supplies. Nothing but this program writes
    a lock file, so an entry that is not a plain file was planted; it is dropped
    and the real lock file made in its place. One that cannot be dropped raises
    `_HostileLockError` rather than passing for the ordinary case, or planting a
    directory under the name would be enough to run every later command
    unsynchronised.

    None is that ordinary case (a read-only filesystem, no permission), which has
    always meant "carry on without a lock" and still does.
    """
    flags = os.O_RDWR | os.O_CREAT
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, flags, 0o644)
        return fd
    except OSError as exc:
        if not _is_planted(exc):
            return None
    if not _drop_planted(dir_fd, name):
        raise _HostileLockError(path)
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, flags, 0o644)
        return fd
    except OSError as exc:
        if _is_planted(exc):
            raise _HostileLockError(path) from None
        return None


def _lock_info_at(dir_fd: int, name: str) -> str:
    """Return a human-readable hint about who holds the lock, or ''.

    Reads the lock file's first line (PID + command name) and returns a
    parenthesised note suitable for appending to an error message. Returns ''
    when the file is missing, empty, not a plain file, or names a dead PID.
    A stopped holder (Ctrl+Z) is called out explicitly with the commands to
    resume or kill it, since it would otherwise hold the lock forever.
    """
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, os.O_RDONLY)
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "r", errors="replace") as fh:
            line = fh.readline().strip()
    except OSError:
        with contextlib.suppress(OSError):
            os.close(fd)
        return ""
    if not line:
        return ""
    fields = line.split(None, 1)
    cmd = fields[1] if len(fields) > 1 else "unknown"
    try:
        pid = int(fields[0])
        os.kill(pid, 0)
    except (OSError, ValueError):
        return ""
    if _pid_state(pid) == "T":
        return (
            f" (PID {pid}: {cmd}, suspended, e.g. by Ctrl+Z; "
            f"resume it with 'kill -CONT {pid}' or terminate it with 'kill {pid}')"
        )
    return f" (PID {pid}: {cmd})"


def _hint_for(parts: tuple[str, ...], name: str) -> str:
    """Return the holder hint for the lock file *name* in one lock directory.

    Cosmetic, so a lock directory that cannot be reached is simply no hint.
    Whether a lock is refused is decided in `acquire()`, which never falls back to
    a guess.
    """
    dir_fd = _locks_dir_fd(parts)
    if dir_fd is None:
        return ""
    try:
        return _lock_info_at(dir_fd, name)
    finally:
        os.close(dir_fd)


def _lock_is_held_at(dir_fd: int, name: str) -> bool:
    """Return True iff *name* under dir_fd is held exclusively by some process.

    A shared, non-blocking flock probe, dropped again immediately rather than
    held across any work: a refusal means an exclusive holder is present,
    success means the file is unheld. Any other errno counts as "not held",
    matching `acquire()`'s rule that a filesystem which ignores flock must not
    stall the caller.
    """
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            return exc.errno in (errno.EACCES, errno.EAGAIN)
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _probe_locks_dir(parts: tuple[str, ...], held: list[tuple[str, str]]) -> None:
    """Append (path, hint) for every held lock in one lock directory."""
    dir_fd = _locks_dir_fd(parts)
    if dir_fd is None:
        return
    try:
        try:
            names = dirfd.listdir_at(dir_fd)
        except OSError:
            return
        for name in names:
            if not name.endswith(".lock"):
                continue
            if _lock_is_held_at(dir_fd, name):
                held.append((os.path.join(RUNTIME_DIR, *parts, name), _lock_info_at(dir_fd, name)))
    finally:
        os.close(dir_fd)


def busy_locks() -> list[tuple[str, str]]:
    """Return (lock_path, hint) for every lock another process holds.

    Both namespaces that guard a write to the download cache are scanned:
    `install` (and `reset`, through it) takes an exclusive ContainerLock, and
    `build` and `push` take an exclusive BuildLock. A RunCacheLock is only ever
    held by a build that already holds a BuildLock, so that directory adds
    nothing. Shared holders (a `login` session, a running `backup`) do not
    answer the probe and are deliberately absent from the result: they never
    touch the cache.

    The answer is a snapshot by construction. It says nothing about a command
    that starts immediately afterwards, so it is a guard against running
    concurrently with work in progress, not a lock.
    """
    held: list[tuple[str, str]] = []
    for parts in (_CONTAINER_PARTS, _BUILD_PARTS):
        _probe_locks_dir(parts, held)
    return held


class _FlockBase:
    """Shared flock(2) machinery for the lock classes below."""

    def __init__(
        self,
        exclusive: bool,
        command: str,
        inheritable: bool,
        blocking: bool = False,
    ) -> None:
        self._exclusive = exclusive
        self._command = command
        self._inheritable = inheritable
        self._blocking = blocking
        self._fd: typing.TextIO | None = None
        self._reentrant = False
        self._hostile = ""
        # Subclasses populate these before acquire() is called.
        self._lock_path: str = ""
        self._dir_parts: tuple[str, ...] = _CONTAINER_PARTS
        self._label: str = "resource"
        self._display: str = ""

    @property
    def lock_path(self) -> str:
        return self._lock_path

    def holder_hint(self) -> str:
        """Parenthesised note naming the lock's holder, or ''."""
        return _hint_for(self._dir_parts, os.path.basename(self._lock_path))

    def acquire(self) -> bool:
        """Try to acquire the lock non-blocking.

        Returns True on success (or when re-entrant / filesystem ignores
        flock). Returns False when blocked by another process, or when the lock
        file's name is occupied by something this module cannot remove: see
        `open_lock_file_at`. __enter__ tells the two apart.
        """
        if self._lock_path in _held_exclusive:
            self._reentrant = True
            return True

        try:
            dir_fd = _locks_dir_fd(self._dir_parts, create=True)
            if dir_fd is None:
                log.warning("Could not create lock directory for '%s'. Proceeding unlocked.", self._lock_path)
                return True
            try:
                # O_CREAT without O_TRUNC: opening with "w" here would wipe the
                # holder's "PID command" line *before* the flock attempt, so a
                # conflicting acquire destroyed the very diagnostics that
                # _lock_info_at() needs to name the busy process. The file is
                # truncated only after the lock is actually ours.
                raw_fd = _open_lock_file(dir_fd, os.path.basename(self._lock_path), self._lock_path)
            finally:
                os.close(dir_fd)
        except _HostileLockError as exc:
            self._hostile = str(exc)
            return False
        if raw_fd is None:
            log.warning("Could not open/create lock file '%s'. Proceeding unlocked.", self._lock_path)
            return True

        try:
            fd = os.fdopen(raw_fd, "r+")
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.close(raw_fd)
            log.warning("Could not open/create lock file '%s': %s. Proceeding unlocked.", self._lock_path, exc)
            return True

        if self._inheritable:
            with contextlib.suppress(OSError):
                os.set_inheritable(fd.fileno(), True)

        lock_op = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
        if not self._blocking:
            lock_op |= fcntl.LOCK_NB
        try:
            fcntl.flock(fd.fileno(), lock_op)
        except OSError as exc:
            fd.close()
            return exc.errno not in (errno.EACCES, errno.EAGAIN)

        try:
            fd.truncate(0)
            fd.seek(0)
            fd.write(f"{os.getpid()} {self._command}\n")
            fd.flush()
        except OSError as exc:
            log.warning("Failed to write PID and command to lock file %s: %s", self._lock_path, exc)

        self._fd = fd
        if self._exclusive:
            _held_exclusive.add(self._lock_path)
        return True

    def release(self) -> None:
        """Release the lock. No-op when re-entrant or not yet acquired."""
        if self._reentrant:
            return
        if self._exclusive:
            _held_exclusive.discard(self._lock_path)
        if self._fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                self._fd.close()
            self._fd = None

    def __enter__(self):
        if not self.acquire():
            if self._hostile:
                raise LockConflictError(
                    f"cannot lock {self._label} '{self._display}': '{self._hostile}' is not a plain "
                    f"file and could not be replaced, so this command cannot be serialised against "
                    f"others. Remove it and try again."
                )
            raise LockConflictError(f"{self._label} '{self._display}' is busy{self.holder_hint()}.")
        return self

    def __exit__(self, *_) -> None:
        self.release()


class ContainerLock(_FlockBase):
    """Advisory lock for a single container name."""

    def __init__(
        self,
        name: str,
        exclusive: bool,
        command: str = "",
        inheritable: bool = False,
    ) -> None:
        super().__init__(
            exclusive=exclusive,
            command=command,
            inheritable=inheritable,
        )
        self._lock_path = container_lock_path(name)
        self._dir_parts = _CONTAINER_PARTS
        self._label = "container"
        self._display = name


class BuildLock(_FlockBase):
    """Advisory exclusive lock for a single (image_ref, arch) build target."""

    def __init__(
        self,
        image_ref: str,
        arch: str,
        command: str = "build",
    ) -> None:
        super().__init__(exclusive=True, command=command, inheritable=False)
        self._lock_path = _build_lock_path(image_ref, arch)
        self._dir_parts = _BUILD_PARTS
        self._label = "image"
        self._display = f"{image_ref} ({arch})"


class RunCacheLock(_FlockBase):
    """Exclusive lock for one RUN --mount=type=cache id (sharing=locked).

    Blocking: BuildKit semantics are "wait for the other builder", not fail.
    """

    def __init__(self, cache_key: str, command: str = "build") -> None:
        super().__init__(exclusive=True, command=command, inheritable=False, blocking=True)
        self._lock_path = os.path.join(_RUN_CACHE_LOCKS_DIR, f"{cache_key}.lock")
        self._dir_parts = _RUN_CACHE_PARTS
        self._label = "build cache"
        self._display = cache_key
