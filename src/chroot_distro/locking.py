# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Advisory flock(2) locks that serialise commands against each other.

Three namespaces, one class each: `ContainerLock` per container name,
`BuildLock` per (image_ref, arch) pair hashed to a short key, `RunCacheLock` per
build-cache key. Their files live under `locks/`, `locks/build/` and
`locks/run-cache/` below RUNTIME_DIR. Container lock files survive `remove`
so the next command can still flock the same inode. Exclusive locks are
re-entrant within one process, keyed by lock path in `_held_exclusive`.

`locks/` is guest-writable on Termux (RUNTIME_DIR sits under the prefix bound
read-write into every non-isolated container) and every name in it is
predictable, so no lock file is ever addressed by path: the directories are
descended O_NOFOLLOW one level at a time and the file is opened as
`(dir_fd, name)` with a plain-file check. Reject unexpected entry types without
removing them. A peer could have installed and locked a regular file since the
failed open, and deleting it would let another caller take a different lock.

Only the advisory `.info` file holds the PID and command. Acquire writes the
record to a fresh inode and renames it into place. A hard link can pass the
plain-file check on the flock inode, so that inode never receives data writes.
Holder hints can be stale or forged and play no part in granting a lock.

Failing open or failing closed is decided per caller, and the difference is the
point of having both `_open_lock_file` and `open_lock_file_at`. An ordinary
refusal (read-only filesystem, no permission, a filesystem that ignores flock)
means "carry on without a lock", so a missing lock never stops the program from
running at all. A lock filename rejected as too long stops acquisition. A
planted name also stops acquisition for a container or build lock. The open
raises `_HostileLockError` and `acquire()` returns False. The build-cache index
uses `open_lock_file_at` and can proceed unlocked because `atomic_write` still
publishes a complete index. A concurrent `record()` may lose its update.

Holder hints read the recorded PID and command. `busy_locks` uses a shared
non-blocking probe to find exclusive locks. Only `acquire()` grants a lock.
"""

import contextlib
import errno
import fcntl
import hashlib
import logging
import os
import re
import stat

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

_HOLDER_PREFIX = b"chroot-distro-lock-v1 "
_HOLDER_RECORD = re.compile(_HOLDER_PREFIX + rb"([0-9]{1,10}) ([A-Za-z0-9_-]{1,64})\n")
_HOLDER_MAX_BYTES = 128

# Absolute lock-file paths for which this process currently holds an
# exclusive flock. Used to make exclusive locking re-entrant within a
# single invocation.
_held_exclusive: set[str] = set()


def container_lock_path(name: str) -> str:
    """Use a leading `~` for hashed names, outside the valid container name grammar."""
    basename = f"{name}.lock"
    if len(os.fsencode(basename)) > dirfd.NAME_MAX:
        basename = f"~{hashlib.sha256(os.fsencode(name)).hexdigest()}.lock"
    return os.path.join(LOCKS_DIR, basename)


def _build_lock_path(image_ref: str, arch: str) -> str:
    """Return the lock-file path for a build of (image_ref, arch).

    The key *is* the manifest-cache key (a 16-hex-char sha256 prefix of the
    canonical reference and the arch), so a build lock identifies the same
    artifact the build writes to, and is derived the same total way: a reference
    off the command line can hold a lone surrogate. Hashing the reference as
    spelled let `build -t myapp` and `push docker.io/library/myapp`, one cache
    entry, take two different locks and run side by side.

    Imported here rather than at the top: the docker package reaches `paths`,
    which imports this module.
    """
    from chroot_distro.helpers.docker.refs import canonical_ref

    key = hashlib.sha256(f"{canonical_ref(image_ref)}_{arch}".encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return os.path.join(_BUILD_LOCKS_DIR, f"{key}.lock")


def container_busy_status(name: str) -> str:
    """Return a short container status for display (``idle`` or ``in use …``)."""
    hint = _hint_for(_CONTAINER_PARTS, os.path.basename(container_lock_path(name)))
    if hint:
        return f"in use{hint}"
    return "idle"


def _pid_state(pid: int) -> str:
    """Return the single-letter process state from /proc/<pid>/stat, or ''.

    'T' means stopped (job control, e.g. Ctrl+Z): the process still holds
    its flocks but will never release them until resumed or killed.
    """
    try:
        with open(f"/proc/{pid}/stat", errors="replace") as fh:
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


def _is_planted(dir_fd: int, name: str, exc: OSError, *, directory: bool = False) -> bool:
    """Check for an unexpected entry type after a failed open."""
    if dirfd.is_refusal(exc) or exc.errno in _PLANTED_ERRNOS:
        return True
    try:
        mode = dirfd.lstat_at(dir_fd, name).st_mode
    except OSError:
        return False
    return not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode))


def _open_lock_subdir(dir_fd: int, name: str, path: str) -> int | None:
    """Open (creating) the lock directory *name* under dir_fd. Descriptor, or None."""
    try:
        try:
            return dirfd.opendir_at(dir_fd, name)
        except FileNotFoundError:
            with contextlib.suppress(FileExistsError):
                os.mkdir(name, dir_fd=dir_fd)
        return dirfd.opendir_at(dir_fd, name)
    except OSError as exc:
        if _is_planted(dir_fd, name, exc, directory=True):
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

    Creating descends level by level and refuses an unexpected entry at any
    level. Reading (`busy_locks`, a holder hint) makes nothing.
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
    are the same. An unexpected entry returns None so the index can still be
    published through `atomic_write`.
    """
    try:
        return _open_lock_file(dir_fd, name, path)
    except _HostileLockError:
        return None
    except OSError as exc:
        if exc.errno != errno.ENAMETOOLONG:
            raise
        return None


def _open_lock_file(dir_fd: int, name: str, path: str) -> int | None:
    """Open the flock inode. NFS requires a writable descriptor for LOCK_EX."""
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, os.O_RDWR | os.O_CREAT)
        return fd
    except OSError as exc:
        if exc.errno == errno.ENAMETOOLONG:
            raise
        if _is_planted(dir_fd, name, exc):
            raise _HostileLockError(path) from None
        return None


def _holder_name(name: str) -> str:
    return f"{name.removesuffix('.lock')}.info"


def _write_lock_info(dir_fd: int, name: str, command: str) -> None:
    record = _HOLDER_PREFIX + f"{os.getpid()} {command or 'unknown'}\n".encode("ascii", errors="replace")
    temp = f".holder-{os.urandom(8).hex()}.tmp"
    fd = dirfd.open_file_at(dir_fd, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        try:
            if os.write(fd, record) != len(record):
                raise OSError(errno.EIO, "short write of lock holder info")
        finally:
            os.close(fd)
        os.replace(temp, _holder_name(name), src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        dirfd.unlink_quietly(dir_fd, temp)
        raise


def _lock_info_at(dir_fd: int, name: str) -> str:
    """Read an advisory holder hint from the bounded sidecar record."""
    try:
        fd, st = dirfd.open_regular_at(dir_fd, _holder_name(name), os.O_RDONLY)
        try:
            if st.st_nlink != 1 or st.st_size > _HOLDER_MAX_BYTES:
                return ""
            record = os.read(fd, _HOLDER_MAX_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        return ""

    fields = _HOLDER_RECORD.fullmatch(record)
    if fields is None:
        return ""
    pid = int(fields[1])
    if not 0 < pid <= 2**31 - 1:
        return ""
    try:
        os.kill(pid, 0)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return ""
    command = fields[2].decode("ascii")
    state = ", suspended" if _pid_state(pid) == "T" else ""
    return f" (PID {pid}: {command}{state})"


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
        self._fd: int | None = None
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
        flock). Returns False on contention or an unusable lock name.
        """
        if self._lock_path in _held_exclusive:
            self._reentrant = True
            return True

        self._hostile = ""
        name = os.path.basename(self._lock_path)
        dir_fd: int | None = None
        try:
            dir_fd = _locks_dir_fd(self._dir_parts, create=True)
            if dir_fd is None:
                log.warning("Could not create lock directory for '%s'. Proceeding unlocked.", self._lock_path)
                return True
            return self._acquire_at(dir_fd, name)
        except _HostileLockError as exc:
            self._hostile = str(exc)
            return False
        except OSError as exc:
            if exc.errno != errno.ENAMETOOLONG:
                raise
            log.warning("Cannot acquire lock '%s': filename is too long for the filesystem.", self._lock_path)
            return False
        finally:
            if dir_fd is not None:
                os.close(dir_fd)

    def _acquire_at(self, dir_fd: int, name: str) -> bool:
        fd = _open_lock_file(dir_fd, name, self._lock_path)
        if fd is None:
            log.warning("Could not open/create lock file '%s'. Proceeding unlocked.", self._lock_path)
            return True

        try:
            if self._inheritable:
                with contextlib.suppress(OSError):
                    os.set_inheritable(fd, True)

            lock_op = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
            if not self._blocking:
                lock_op |= fcntl.LOCK_NB
            try:
                fcntl.flock(fd, lock_op)
            except OSError as exc:
                return exc.errno not in (errno.EACCES, errno.EAGAIN)

            try:
                _write_lock_info(dir_fd, name, self._command)
            except OSError as exc:
                log.warning("Failed to publish holder info for '%s': %s", self._lock_path, exc)

            if self._exclusive:
                _held_exclusive.add(self._lock_path)
            self._fd = fd
            return True
        finally:
            if self._fd != fd:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def release(self) -> None:
        """Release the lock. No-op when re-entrant or not yet acquired."""
        if self._reentrant:
            return
        if self._exclusive:
            _held_exclusive.discard(self._lock_path)
        if self._fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None

    def conflict_error(self) -> LockConflictError:
        """Describe the failure from the last acquisition attempt."""
        if self._hostile:
            return LockConflictError(
                f"cannot lock {self._label} '{self._display}': unexpected entry at '{self._hostile}'. "
                "Stop other chroot-distro commands, inspect the entry, and remove it if misplaced."
            )
        return LockConflictError(f"{self._label} '{self._display}' is busy{self.holder_hint()}.")

    def __enter__(self):
        if not self.acquire():
            raise self.conflict_error()
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
