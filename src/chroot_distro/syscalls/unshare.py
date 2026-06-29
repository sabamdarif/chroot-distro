"""Wrappers around ``unshare(2)`` for Linux namespace creation.

This module provides high-level helpers that combine ``unshare(2)`` with
``fork(2)`` to safely create and enter new namespaces.  All syscalls go
through :mod:`chroot_distro.syscalls._libc` so the process-wide libc
handle is reused.

Functions
---------
native_unshare
    Thin wrapper around ``unshare(2)``.
unshare_and_fork
    Unshare namespaces and fork when a PID namespace is requested.
probe_namespace_support
    Discover which namespace flags the running kernel/user supports.
create_holder_process
    Spawn a long-lived "holder" process that keeps namespaces alive.
"""

from __future__ import annotations

import logging
import os
import signal
import time

from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_REC,
    NS_FILE_MAP,
)
from chroot_distro.syscalls._libc import (
    check_syscall,
    get_libc,
    libc_mount,
    libc_sethostname,
    py_unshare,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. native_unshare – thin wrapper
# ---------------------------------------------------------------------------


def native_unshare(flags: int) -> None:
    """Call ``unshare(2)`` to disassociate the calling process from namespaces.

    This is a thin convenience wrapper around :func:`py_unshare` that
    exists so callers within this package need not import from ``_libc``
    directly.

    Args:
        flags: A bitmask of ``CLONE_NEW*`` constants specifying which
            namespaces to unshare.

    Raises:
        OSError: If the underlying ``unshare(2)`` syscall fails (e.g.
            ``EPERM``, ``EINVAL``).
    """
    py_unshare(flags)


# ---------------------------------------------------------------------------
# 2. unshare_and_fork – namespace creation with optional PID-ns fork
# ---------------------------------------------------------------------------


def unshare_and_fork(
    flags: int,
    *,
    propagation: int = MS_REC | MS_PRIVATE,
) -> int:
    """Unshare namespaces and fork if a PID namespace is included.

    When ``CLONE_NEWPID`` is present in *flags* the first child process
    created after ``unshare(2)`` becomes PID 1 in the new PID namespace.
    This function handles the fork transparently:

    * **Parent** – returns the child's PID (positive integer).
    * **Child**  – resets mount propagation to *propagation* and returns 0.

    If ``CLONE_NEWPID`` is **not** in *flags* no fork occurs and the
    function returns ``0`` in the (sole) calling process.

    Args:
        flags: ``CLONE_NEW*`` bitmask passed to ``unshare(2)``.
        propagation: Mount-propagation flags applied in the child process
            after the fork.  Defaults to ``MS_REC | MS_PRIVATE`` so that
            subsequent mounts are invisible to the parent mount namespace.

    Returns:
        The child PID in the parent process, or ``0`` in the child (or in
        the calling process when no fork takes place).

    Raises:
        OSError: If ``unshare(2)`` or ``fork(2)`` fails.
    """
    py_unshare(flags)

    if not (flags & CLONE_NEWPID):
        return 0

    pid = os.fork()
    if pid > 0:
        # Parent – return child PID.
        return pid

    # Child (PID 1 inside the new PID namespace).
    try:
        libc_mount(None, b"/", None, propagation, None)
    except OSError:
        pass  # Best-effort; may fail if mount NS was not unshared.

    return 0


# ---------------------------------------------------------------------------
# 3. probe_namespace_support – discover supported CLONE_NEW* flags
# ---------------------------------------------------------------------------


def probe_namespace_support(flags: int) -> int:
    """Test which ``CLONE_NEW*`` namespace flags the kernel supports.

    For **each** bit set in *flags* a throw-away child process is forked
    and attempts ``unshare(bit)``.  The child exits with status ``0`` on
    success or ``1`` on failure.  The parent collects the results and
    returns a bitmask of the flags that succeeded.

    This replaces the legacy pattern of spawning ``unshare --flag true``
    as a subprocess.

    Args:
        flags: A bitmask of ``CLONE_NEW*`` constants to probe.

    Returns:
        A bitmask containing only the flags that were successfully
        unshared in the throw-away children.
    """
    supported: int = 0

    bit = 1
    while bit <= flags:
        if not (flags & bit):
            bit <<= 1
            continue

        pid = os.fork()
        if pid == 0:
            # Child – attempt the unshare and exit.
            try:
                py_unshare(bit)
            except OSError:
                os._exit(1)
            os._exit(0)

        # Parent – wait for the child.
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
            supported |= bit
            log.debug(
                "namespace flag 0x%08x supported",
                bit,
            )
        else:
            log.debug(
                "namespace flag 0x%08x not supported",
                bit,
            )

        bit <<= 1

    return supported


# ---------------------------------------------------------------------------
# 4. create_holder_process – long-lived namespace holder
# ---------------------------------------------------------------------------


def create_holder_process(
    flags: int,
    *,
    rootfs: str | None = None,
    ready_fd: int = -1,
) -> int:
    """Create a long-lived process that holds namespaces open.

    The holder process calls ``unshare(2)`` with *flags*, optionally
    ``chroot``\\ s into *rootfs* for maximum isolation, and then sleeps
    forever.  Other processes can later join its namespaces via
    ``/proc/<pid>/ns/*``.

    Synchronisation
    ~~~~~~~~~~~~~~~
    The holder writes a single byte (``b'K'``) to signal readiness:

    * If *ready_fd* ≥ 0 the byte is written there (caller owns the fd).
    * Otherwise an internal ``os.pipe()`` is used and the parent blocks
      on the read end until the holder is ready.

    PID namespace handling
    ~~~~~~~~~~~~~~~~~~~~~~
    When ``CLONE_NEWPID`` is included in *flags* an extra fork is
    performed so the actual holder becomes PID 1 inside the new PID
    namespace.  The intermediate "launcher" process waits for the holder
    to signal readiness before exiting, which lets the original parent
    detect launch failures via ``os.waitpid``.

    Args:
        flags: ``CLONE_NEW*`` bitmask for ``unshare(2)``.
        rootfs: Optional path to a root filesystem.  When given the
            holder calls ``os.chroot(rootfs)`` followed by ``os.chdir('/')``.
        ready_fd: File descriptor to write the ready byte to.  When set
            to ``-1`` (the default) an internal pipe is created.

    Returns:
        The PID of the holder process (the one that is sleeping).

    Raises:
        OSError: If ``unshare(2)`` or ``fork(2)`` fails, or if the
            holder process exits before signalling readiness.
        RuntimeError: If the holder fails to start.
    """
    # --- Set up synchronisation pipe if the caller did not provide one. ---
    if ready_fd >= 0:
        pipe_r: int | None = None
        notify_fd = ready_fd
    else:
        pipe_r, notify_fd = os.pipe()

    launcher_pid = os.fork()
    if launcher_pid > 0:
        # ---- Original (parent) process ----
        if notify_fd != ready_fd:
            # We own the write end in the parent – close it so we see EOF
            # if the child dies without writing.
            os.close(notify_fd)

        if pipe_r is not None:
            # Block until the holder signals readiness.
            try:
                data = os.read(pipe_r, 1)
            finally:
                os.close(pipe_r)
            if data != b"K":
                # The holder died before becoming ready.
                _reap_child(launcher_pid)
                raise RuntimeError(
                    "namespace holder process failed to start "
                    "(no readiness signal received)"
                )

        # The holder may be the launcher itself or a grandchild.  If
        # CLONE_NEWPID was requested the grandchild is the real holder
        # and its PID was sent through the pipe by the launcher.  For
        # the simple (no PID-ns) case the launcher *is* the holder.
        #
        # We always return launcher_pid because:
        #   • Without PID-ns: launcher == holder.
        #   • With PID-ns: the launcher is the direct child we can
        #     waitpid() on; the grandchild (PID 1 in the new ns) is
        #     reachable via /proc/<launcher_pid>/ns/*.
        return launcher_pid

    # ---- Launcher (child) process ----
    # Close the read end of the pipe if we created one.
    if pipe_r is not None:
        os.close(pipe_r)

    try:
        py_unshare(flags)
    except OSError:
        log.exception("unshare failed in launcher")
        os._exit(1)

    if flags & CLONE_NEWPID:
        # Fork again so the grandchild becomes PID 1 in the new PID
        # namespace.
        grandchild_pid = os.fork()
        if grandchild_pid > 0:
            # Launcher: wait for the grandchild to signal readiness,
            # then exit.  Keeping the launcher alive until the holder
            # is ready lets the original parent detect failures.
            #
            # The grandchild will write to notify_fd, so we do NOT
            # close it here – just wait and exit.
            try:
                _, status = os.waitpid(grandchild_pid, 0)
            except ChildProcessError:
                pass
            os._exit(0)

        # Grandchild – this is the actual holder (PID 1).
        _run_holder(notify_fd, rootfs)
    else:
        # No PID namespace – the launcher itself is the holder.
        _run_holder(notify_fd, rootfs)

    # Should never be reached.
    os._exit(1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_holder(notify_fd: int, rootfs: str | None) -> None:
    """Execute the holder loop: set propagation, chroot, signal, sleep.

    This function never returns – it either sleeps forever or calls
    ``os._exit``.

    Args:
        notify_fd: File descriptor to write the readiness byte to.
        rootfs: Optional root filesystem to ``chroot`` into.
    """
    # 1. Set mount propagation to private.
    try:
        libc_mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
    except OSError:
        pass  # Best-effort.

    # 2. Isolate into rootfs if requested.
    if rootfs is not None:
        try:
            os.chroot(rootfs)
            os.chdir("/")
        except OSError:
            log.exception("chroot into %s failed", rootfs)
            os._exit(1)

    # 3. Signal readiness.
    try:
        os.write(notify_fd, b"K")
    except OSError:
        log.exception("failed to write readiness signal")
        os._exit(1)
    finally:
        os.close(notify_fd)

    # 4. Sleep forever.  The process keeps the namespaces alive until it
    #    is explicitly killed.
    log.debug("holder process %d entering sleep loop", os.getpid())
    try:
        while True:
            time.sleep(2147483647)
    except (KeyboardInterrupt, SystemExit):
        pass
    os._exit(0)


def _reap_child(pid: int) -> None:
    """Wait for *pid* without raising on unexpected statuses.

    Args:
        pid: The child PID to reap.
    """
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
