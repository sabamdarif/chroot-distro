# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Single libc handle, the errno check every wrapper uses, and two backports.

One `ctypes.CDLL` is built per process with `use_errno=True`, under a lock, so
`ctypes.get_errno()` reads the thread-local errno of the call that just returned
and no module ends up holding a second handle. `check_syscall` turns the libc
convention (-1 plus errno) into an OSError that names the raw syscall,
`mount(2)` rather than `mount`, so a failure can never be read as the output of a
command-line tool this program does not run. `libc_prctl` is the deliberate
exception: prctl(2) returns meaningful non-negative values, so it hands the raw
result back unchecked and the caller interprets it.

os.unshare and os.setns arrived in Python 3.12. Below that they are called through
ctypes here, so nothing above this file needs a version check.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno as _errno_mod
import os
import sys
import threading

_libc_lock = threading.Lock()
_libc_handle: ctypes.CDLL | None = None


def get_libc() -> ctypes.CDLL:
    """Return a process-wide cached ``ctypes.CDLL`` handle for libc.

    The handle is created with ``use_errno=True`` so that ``ctypes.get_errno()``
    returns the thread-local errno after each call.
    """
    global _libc_handle  # noqa: PLW0603
    if _libc_handle is not None:
        return _libc_handle
    with _libc_lock:
        if _libc_handle is not None:
            return _libc_handle  # type: ignore[unreachable]
        name = ctypes.util.find_library("c")
        if name is None:
            # Fallback: on many Linux systems the soname is predictable.
            name = "libc.so.6"
        _libc_handle = ctypes.CDLL(name, use_errno=True)
        return _libc_handle


def check_syscall(result: int, func_name: str) -> None:
    """Raise :class:`OSError` if *result* indicates a failed syscall.

    Conventional libc wrappers return ``-1`` on failure and set ``errno``.
    This helper reads the thread-local errno via ``ctypes.get_errno()``
    and raises a descriptive :class:`OSError`.

    The message names the raw syscall (``mount(2)``, ``umount2(2)``, …) and
    the symbolic errno so failures are never mistaken for output of the
    corresponding command-line tools, which chroot-distro does not use.
    """
    if result == -1:
        err = ctypes.get_errno()
        code = _errno_mod.errorcode.get(err, f"errno {err}")
        raise OSError(err, f"{func_name}(2): {os.strerror(err)} ({code})")


# Python 3.10-3.11 backports for os.unshare / os.setns

if sys.version_info >= (3, 12):
    from os import setns as py_setns
    from os import unshare as py_unshare
else:

    def py_unshare(flags: int) -> None:
        """Call ``unshare(2)`` directly using ctypes."""
        libc = get_libc()
        result = libc.unshare(ctypes.c_int(flags))
        check_syscall(result, "unshare")

    def py_setns(fd: int, nstype: int) -> None:
        """Call ``setns(2)`` directly using ctypes."""
        libc = get_libc()
        result = libc.setns(ctypes.c_int(fd), ctypes.c_int(nstype))
        check_syscall(result, "setns")


def libc_mount(
    source: bytes | None,
    target: bytes,
    fstype: bytes | None,
    flags: int,
    data: bytes | None,
) -> None:
    """Call Linux ``mount(2)`` via ctypes."""
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
    """Call Linux ``umount2(2)`` via ctypes."""
    libc = get_libc()
    result = libc.umount2(target, ctypes.c_int(flags))
    check_syscall(result, "umount2")


def libc_sethostname(name: str) -> None:
    """Call Linux ``sethostname(2)`` via ctypes."""
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
    return int(
        libc.prctl(
            ctypes.c_int(option),
            ctypes.c_ulong(padded[0]),
            ctypes.c_ulong(padded[1]),
            ctypes.c_ulong(padded[2]),
            ctypes.c_ulong(padded[3]),
        )
    )
