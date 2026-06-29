"""Shared libc handle, errno helper, and Python 3.10–3.11 backports.

Every syscall module in this package imports its libc handle and error
checking from here, ensuring a single ``ctypes.CDLL`` instance is reused
across the process.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading

# ---------------------------------------------------------------------------
# Cached libc handle
# ---------------------------------------------------------------------------

_libc_lock = threading.Lock()
_libc_handle: ctypes.CDLL | None = None


def get_libc() -> ctypes.CDLL:
    """Return a process-wide cached ``ctypes.CDLL`` handle for libc.

    The handle is created with ``use_errno=True`` so that ``ctypes.get_errno()``
    returns the thread-local errno after each call.
    """
    global _libc_handle
    if _libc_handle is not None:
        return _libc_handle
    with _libc_lock:
        if _libc_handle is not None:  # double-check
            return _libc_handle
        name = ctypes.util.find_library("c")
        if name is None:
            # Fallback: on many Linux systems the soname is predictable.
            name = "libc.so.6"
        _libc_handle = ctypes.CDLL(name, use_errno=True)
        return _libc_handle


# ---------------------------------------------------------------------------
# errno helper
# ---------------------------------------------------------------------------


def check_syscall(result: int, func_name: str) -> None:
    """Raise :class:`OSError` if *result* indicates a failed syscall.

    Conventional libc wrappers return ``-1`` on failure and set ``errno``.
    This helper reads the thread-local errno via ``ctypes.get_errno()``
    and raises a descriptive :class:`OSError`.
    """
    if result == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"{func_name}: {os.strerror(errno)}")


# ---------------------------------------------------------------------------
# Python 3.10–3.11 backports for os.unshare / os.setns
# ---------------------------------------------------------------------------

if sys.version_info >= (3, 12):
    # Python 3.12+ exposes these natively.
    py_unshare = os.unshare  # type: ignore[attr-defined]
    py_setns = os.setns  # type: ignore[attr-defined]
else:

    def py_unshare(flags: int) -> None:
        """Call ``unshare(2)`` via ctypes (backport for Python < 3.12)."""
        libc = get_libc()
        result = libc.unshare(ctypes.c_int(flags))
        check_syscall(result, "unshare")

    def py_setns(fd: int, nstype: int = 0) -> None:
        """Call ``setns(2)`` via ctypes (backport for Python < 3.12)."""
        libc = get_libc()
        result = libc.setns(ctypes.c_int(fd), ctypes.c_int(nstype))
        check_syscall(result, "setns")


# ---------------------------------------------------------------------------
# Additional raw syscall wrappers not in the os module
# ---------------------------------------------------------------------------


def libc_mount(
    source: bytes | None,
    target: bytes,
    fstype: bytes | None,
    flags: int,
    data: bytes | None,
) -> None:
    """Call ``mount(2)`` via ctypes.

    All string arguments must already be encoded to ``bytes``.
    """
    libc = get_libc()
    result = libc.mount(
        source,
        target,
        fstype,
        ctypes.c_ulong(flags),
        data,
    )
    check_syscall(result, "mount")


def libc_umount2(target: bytes, flags: int) -> None:
    """Call ``umount2(2)`` via ctypes.

    *target* must be an encoded bytes path.
    """
    libc = get_libc()
    result = libc.umount2(target, ctypes.c_int(flags))
    check_syscall(result, "umount2")


def libc_sethostname(name: str) -> None:
    """Call ``sethostname(2)`` via ctypes."""
    libc = get_libc()
    name_bytes = name.encode()
    result = libc.sethostname(name_bytes, len(name_bytes))
    check_syscall(result, "sethostname")


def libc_prctl(option: int, *args: int) -> int:
    """Call ``prctl(2)`` via ctypes.

    Returns the raw integer result (interpretation is option-dependent).
    Does **not** call :func:`check_syscall` because some prctl operations
    return non-negative values on success.
    """
    libc = get_libc()
    # prctl takes up to 5 unsigned long arguments after the option.
    padded = list(args) + [0] * (4 - len(args))
    return libc.prctl(
        ctypes.c_int(option),
        ctypes.c_ulong(padded[0]),
        ctypes.c_ulong(padded[1]),
        ctypes.c_ulong(padded[2]),
        ctypes.c_ulong(padded[3]),
    )
