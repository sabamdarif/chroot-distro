import contextlib
import errno
import fcntl
import hashlib
import os
import typing

from chroot_distro.constants import RUNTIME_DIR
from chroot_distro.exceptions import LockConflictError

LOCKS_DIR = os.path.join(RUNTIME_DIR, "locks")
_BUILD_LOCKS_DIR = os.path.join(LOCKS_DIR, "build")

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


def read_lock_info(lock_path: str) -> str:
    """Return a human-readable hint about who holds the lock, or ''.

    Reads the lock file's first line (PID + command name) and returns
    a parenthesised note suitable for appending to an error message.
    Returns '' when the file is missing, empty, or names a dead PID.
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
            return f" (PID {pid}: {cmd})"
        except (OSError, ValueError):
            return ""
    except OSError:
        return ""


class _FlockBase:
    """Shared flock(2) machinery for the lock classes below."""

    def __init__(
        self,
        exclusive: bool,
        command: str,
        inheritable: bool,
    ) -> None:
        self._exclusive = exclusive
        self._command = command
        self._inheritable = inheritable
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
        except OSError:
            return True  # Cannot create locks dir; proceed unlocked.

        try:
            fd = open(self._lock_path, "w")  # noqa: SIM115
        except OSError:
            return True  # Cannot open/create lock file; proceed unlocked.

        if self._inheritable:
            with contextlib.suppress(OSError):
                os.set_inheritable(fd.fileno(), True)


        lock_op = (
            (fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        )
        try:
            fcntl.flock(fd.fileno(), lock_op)
        except OSError as exc:
            fd.close()
            return exc.errno not in (errno.EACCES, errno.EAGAIN)

        # Record PID + command in the file for diagnostic purposes.
        try:
            fd.write(f"{os.getpid()} {self._command}\n")
            fd.flush()
        except OSError:
            pass

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
