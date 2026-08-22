import contextlib
import errno
import fcntl
import hashlib
import logging
import os
import typing

from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.exceptions import LockConflictError

log = logging.getLogger(__name__)

LOCKS_DIR = os.path.join(RUNTIME_DIR, "locks")
_BUILD_LOCKS_DIR = os.path.join(LOCKS_DIR, "build")
_RUN_CACHE_LOCKS_DIR = os.path.join(LOCKS_DIR, "run-cache")

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
    hint = read_lock_info(container_lock_path(name))
    if hint:
        return f"in use{hint}"
    return "idle"


def _pid_state(pid: int) -> str:
    """Return the single-letter process state from /proc/<pid>/stat, or ''.

    'T' means stopped (job control, e.g. Ctrl+Z) — the process still holds
    its flocks but will never release them until resumed or killed.
    """
    try:
        with open(f"/proc/{pid}/stat") as fh:
            stat = fh.read()
        # Field 3 follows the parenthesised comm, which may contain spaces.
        return stat.rpartition(")")[2].split()[0]
    except (OSError, IndexError):
        return ""


def read_lock_info(lock_path: str) -> str:
    """Return a human-readable hint about who holds the lock, or ''.

    Reads the lock file's first line (PID + command name) and returns
    a parenthesised note suitable for appending to an error message.
    Returns '' when the file is missing, empty, or names a dead PID.
    A stopped holder (Ctrl+Z) is called out explicitly with the commands
    to resume or kill it, since it would otherwise hold the lock forever.
    """
    try:
        with open(lock_path) as fh:
            line = fh.readline().strip()
        if not line:
            return ""
        parts = line.split(None, 1)
        pid_str = parts[0]
        cmd = parts[1] if len(parts) > 1 else "unknown"
        try:
            pid = int(pid_str)
            os.kill(pid, 0)
            if _pid_state(pid) == "T":
                return (
                    f" (PID {pid}: {cmd} — suspended, e.g. by Ctrl+Z; "
                    f"resume it with 'kill -CONT {pid}' or terminate it with 'kill {pid}')"
                )
            return f" (PID {pid}: {cmd})"
        except (OSError, ValueError):
            return ""
    except OSError:
        return ""


def _lock_is_held(lock_path: str) -> bool:
    """Return True iff *lock_path* is held exclusively by some process.

    A shared, non-blocking flock probe, dropped again immediately rather than
    held across any work: a refusal means an exclusive holder is present,
    success means the file is unheld. Any other errno counts as "not held",
    matching `acquire()`'s rule that a filesystem which ignores flock must not
    stall the caller.
    """
    try:
        fd = os.open(lock_path, os.O_RDONLY)
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


def busy_locks() -> list[tuple[str, str]]:
    """Return (lock_path, hint) for every lock another process holds.

    Both namespaces that guard a write to the download cache are scanned:
    `install` (and `reset`, through it) takes an exclusive ContainerLock, and
    `build` and `push` take an exclusive BuildLock. A RunCacheLock is only ever
    held by a build that already holds a BuildLock, so that directory adds
    nothing. Shared holders -- a `login` session, a running `backup` -- do not
    answer the probe and are deliberately absent from the result: they never
    touch the cache.

    The answer is a snapshot by construction. It says nothing about a command
    that starts immediately afterwards, so it is a guard against running
    concurrently with work in progress, not a lock.
    """
    held: list[tuple[str, str]] = []
    for directory in (LOCKS_DIR, _BUILD_LOCKS_DIR):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".lock"):
                continue
            path = os.path.join(directory, name)
            if _lock_is_held(path):
                held.append((path, read_lock_info(path)))
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
        # Subclasses populate these before acquire() is called.
        self._lock_path: str = ""
        self._label: str = "resource"
        self._display: str = ""

    @property
    def lock_path(self) -> str:
        return self._lock_path

    def acquire(self) -> bool:
        """Try to acquire the lock non-blocking.

        Returns True on success (or when re-entrant / filesystem ignores
        flock). Returns False when blocked by another process.
        """
        if self._lock_path in _held_exclusive:
            # This process already holds an exclusive lock on this path.
            self._reentrant = True
            return True

        try:
            os.makedirs(os.path.dirname(self._lock_path), exist_ok=True)
        except OSError as exc:
            log.warning("Could not create lock directory '%s': %s. Proceeding unlocked.", os.path.dirname(self._lock_path), exc)
            return True  # Cannot create locks dir; proceed unlocked.

        try:
            # O_CREAT without O_TRUNC: opening with "w" here would wipe the
            # holder's "PID command" line *before* the flock attempt, so a
            # conflicting acquire destroyed the very diagnostics that
            # read_lock_info() needs to name the busy process. The file is
            # truncated only after the lock is actually ours.
            raw_fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o644)
            fd = os.fdopen(raw_fd, "r+")
        except OSError as exc:
            log.warning("Could not open/create lock file '%s': %s. Proceeding unlocked.", self._lock_path, exc)
            return True  # Cannot open/create lock file; proceed unlocked.

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

        # Record PID + command in the file for diagnostic purposes.
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
            hint = read_lock_info(self._lock_path)
            raise LockConflictError(f"{self._label} '{self._display}' is busy{hint}.")
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
        self._label = "image"
        self._display = f"{image_ref} ({arch})"


class RunCacheLock(_FlockBase):
    """Exclusive lock for one RUN --mount=type=cache id (sharing=locked).

    Blocking: BuildKit semantics are "wait for the other builder", not fail.
    """

    def __init__(self, cache_key: str, command: str = "build") -> None:
        super().__init__(exclusive=True, command=command, inheritable=False, blocking=True)
        self._lock_path = os.path.join(_RUN_CACHE_LOCKS_DIR, f"{cache_key}.lock")
        self._label = "build cache"
        self._display = cache_key
