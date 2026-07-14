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

import contextlib
import logging
import os
import time

from chroot_distro.syscalls._constants import (
    CLONE_NEWPID,
    CLONE_NEWUSER,
    MS_PRIVATE,
    MS_REC,
)
from chroot_distro.syscalls._libc import (
    libc_mount,
    py_unshare,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. native_unshare - thin wrapper
# ---------------------------------------------------------------------------


def native_unshare(flags: int) -> None:
    """Call ``unshare(2)`` directly.

    Args:
        flags: A bitmask of ``CLONE_NEW*`` constants specifying which
            namespaces to unshare.

    Raises:
        OSError: If the underlying ``unshare(2)`` syscall fails (e.g.
            ``EPERM``, ``EINVAL``).
    """
    py_unshare(flags)


# ---------------------------------------------------------------------------
# 2. unshare_and_fork - namespace creation with optional PID-ns fork
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

    * **Parent** - returns the child's PID (positive integer).
    * **Child**  - resets mount propagation to *propagation* and returns 0.

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
        # Parent - return child PID.
        return pid

    # Child (PID 1 inside the new PID namespace).
    with contextlib.suppress(OSError):
        libc_mount(None, b"/", None, propagation, None)

    return 0


# ---------------------------------------------------------------------------
# 3. probe_namespace_support - discover supported CLONE_NEW* flags
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
            # Child - attempt the unshare and exit.
            try:
                py_unshare(bit)
            except OSError:
                os._exit(1)
            os._exit(0)

        # Parent - wait for the child.
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
# 3a. _write_id_mappings - user namespace uid/gid mapping
# ---------------------------------------------------------------------------


def _default_id_map() -> tuple[str, str]:
    """Fallback uid/gid map: container uid/gid 0 → the caller's real uid/gid.

    Single-id identity map used when no explicit map is supplied. Kept for
    backward compatibility; the tiered maps are computed by
    :func:`chroot_distro.helpers.namespace.resolve_userns_map`.
    """
    line = f"0 {os.getuid()} 1\n"
    gline = f"0 {os.getgid()} 1\n"
    return line, gline


def _write_id_mappings(child_pid: int, id_map: tuple[str, str] | None = None) -> None:
    """Write uid/gid mappings for a new user namespace.

    *id_map* is a ``(uid_map, gid_map)`` pair of newline-terminated map bodies
    (e.g. ``("0 100000 65536\\n", "0 100000 65536\\n")``). When omitted, a
    single-id identity map (container 0 → caller's real uid) is written.

    Must be called from the **parent** process after the child has called
    ``unshare(CLONE_NEWUSER)`` but before the child calls ``exec``.

    The ordering is mandated by the kernel: (setgroups) → uid_map → gid_map.

    ``setgroups`` handling: writing a gid_map requires ``setgroups`` to be
    ``deny`` *unless* the writer has ``CAP_SETGID`` in the parent user
    namespace. A privileged (root) parent has it, so we leave ``setgroups``
    at ``allow`` — otherwise the container's own ``login``/``su`` cannot call
    ``setgroups(2)`` to set supplementary groups (it fails with EPERM). An
    unprivileged parent must write ``deny`` for the gid_map write to succeed.
    """
    uid_map, gid_map = id_map if id_map is not None else _default_id_map()

    if os.getuid() != 0:
        # Unprivileged: setgroups must be denied before gid_map can be written.
        try:
            with open(f"/proc/{child_pid}/setgroups", "w") as fh:
                fh.write("deny")
        except OSError:
            log.debug("Failed to write setgroups deny for pid %d (may not be required)", child_pid)

    with open(f"/proc/{child_pid}/uid_map", "w") as fh:
        fh.write(uid_map)

    with open(f"/proc/{child_pid}/gid_map", "w") as fh:
        fh.write(gid_map)


# ---------------------------------------------------------------------------
# 4. create_holder_process - long-lived namespace holder
# ---------------------------------------------------------------------------


def create_holder_process(
    flags: int,
    *,
    rootfs: str | None = None,
    ready_fd: int = -1,
    id_map: tuple[str, str] | None = None,
) -> int:
    """Create a long-lived process that holds namespaces open.

    The holder process calls ``unshare(2)`` with *flags*, optionally
    ``chroot``\\ s into *rootfs* for maximum isolation, and then sleeps
    forever.  Other processes can later join its namespaces via
    ``/proc/<pid>/ns/*``.

    Synchronisation
    ~~~~~~~~~~~~~~~
    The holder (or launcher) signals readiness and communicates the holder's
    host PID to the parent using an internal pipe.

    * If *ready_fd* ≥ 0 the byte ``b'K'`` is also written there.

    PID namespace handling
    ~~~~~~~~~~~~~~~~~~~~~~
    When ``CLONE_NEWPID`` is included in *flags* an extra fork is
    performed so the actual holder becomes PID 1 inside the new PID
    namespace.  The intermediate "launcher" process waits for the holder
    to signal readiness, sends the holder's host PID back to the parent,
    and then exits.

    Args:
        flags: ``CLONE_NEW*`` bitmask for ``unshare(2)``.
        rootfs: Optional path to a root filesystem.  When given the
            holder calls ``os.chroot(rootfs)`` followed by ``os.chdir('/')``.
        ready_fd: File descriptor to write the ready byte to.  When set
            to ``-1`` (the default) an internal pipe is created.

    Returns:
        The host PID of the actual holder process (the one that is sleeping).

    Raises:
        OSError: If ``unshare(2)`` or ``fork(2)`` fails, or if the
            holder process exits before signalling readiness.
        RuntimeError: If the holder fails to start.
    """
    # Pipe to send the actual holder's host PID back to the parent.
    pid_r, pid_w = os.pipe()

    # If user namespace is requested, create a dedicated pipe for id-mapping
    # synchronisation.  The parent writes 'M' after writing uid/gid maps;
    # the child waits for it before proceeding.
    has_userns = bool(flags & CLONE_NEWUSER)
    map_r = map_w = -1
    if has_userns:
        map_r, map_w = os.pipe()

    launcher_pid = os.fork()
    if launcher_pid > 0:
        # ---- Original (parent) process ----
        os.close(pid_w)
        if map_r >= 0:
            os.close(map_r)  # Parent only writes map_w.

        if has_userns:
            # The child will unshare(CLONE_NEWUSER) and then send its PID
            # so we can write uid/gid mappings.
            try:
                data = os.read(pid_r, 64)
            except OSError:
                data = b""

            if not data:
                os.close(pid_r)
                if map_w >= 0:
                    os.close(map_w)
                _reap_child(launcher_pid)
                raise RuntimeError("namespace holder process failed to start (no readiness signal received)")

            decoded = data.decode().strip()

            if decoded.startswith("MAP:"):
                try:
                    child_pid = int(decoded.split(":")[1])
                except (IndexError, ValueError) as exc:
                    os.close(pid_r)
                    if map_w >= 0:
                        os.close(map_w)
                    _reap_child(launcher_pid)
                    raise RuntimeError(f"Invalid MAP request from child: {decoded!r}") from exc

                # Write uid/gid mappings for the child's user namespace.
                try:
                    _write_id_mappings(child_pid, id_map)
                except OSError as exc:
                    log.warning("Failed to write id mappings for pid %d: %s", child_pid, exc)

                # Signal the child that mappings are written.
                if map_w >= 0:
                    with contextlib.suppress(OSError):
                        os.write(map_w, b"M")
                    os.close(map_w)
                    map_w = -1

                # Now read the actual holder PID.
                try:
                    data2 = os.read(pid_r, 32)
                except OSError:
                    data2 = b""
                os.close(pid_r)

                if not data2:
                    _reap_child(launcher_pid)
                    raise RuntimeError("namespace holder failed after id mapping")

                try:
                    holder_pid = int(data2.decode().strip())
                except ValueError as exc:
                    _reap_child(launcher_pid)
                    raise RuntimeError(f"holder sent invalid PID after mapping: {data2!r}") from exc
            else:
                # Child decided not to use user namespace (fallback).
                os.close(pid_r)
                if map_w >= 0:
                    os.close(map_w)
                    map_w = -1
                try:
                    holder_pid = int(decoded)
                except ValueError as exc:
                    _reap_child(launcher_pid)
                    raise RuntimeError(f"namespace holder sent invalid PID: {data!r}") from exc
        else:
            # No user namespace -- simple path.
            try:
                data = os.read(pid_r, 32)
            finally:
                os.close(pid_r)

            if not data:
                _reap_child(launcher_pid)
                raise RuntimeError("namespace holder process failed to start (no readiness signal received)")

            try:
                holder_pid = int(data.decode().strip())
            except ValueError as exc:
                _reap_child(launcher_pid)
                raise RuntimeError(f"namespace holder process sent invalid PID: {data!r}") from exc

        # If the caller provided a ready_fd, write the ready byte.
        if ready_fd >= 0:
            try:
                os.write(ready_fd, b"K")
            except OSError:
                log.exception("failed to write to caller ready_fd")

        return holder_pid

    # ---- Launcher (child) process ----
    os.close(pid_r)
    if map_w >= 0:
        os.close(map_w)  # Child only reads map_r.

    try:
        py_unshare(flags)
    except OSError:
        if has_userns:
            # User namespace may have caused the failure -- retry without it.
            log.warning(
                "unshare with CLONE_NEWUSER failed; retrying without user "
                "namespace. Container root will have real host capabilities."
            )
            flags &= ~CLONE_NEWUSER
            has_userns = False
            if map_r >= 0:
                os.close(map_r)
                map_r = -1
            try:
                py_unshare(flags)
            except OSError:
                log.exception("unshare failed in launcher (second attempt)")
                os._exit(1)
        else:
            log.exception("unshare failed in launcher")
            os._exit(1)

    if has_userns:
        # Tell the parent our PID so it can write uid/gid mappings.
        launcher_pid_val = os.getpid()
        try:
            os.write(pid_w, f"MAP:{launcher_pid_val}\n".encode())
        except OSError:
            log.exception("failed to send MAP request to parent")
            os._exit(1)

        # Wait for the parent to finish writing mappings.
        if map_r >= 0:
            try:
                signal_byte = os.read(map_r, 1)
            except OSError:
                signal_byte = b""
            finally:
                os.close(map_r)
                map_r = -1

            if signal_byte != b"M":
                log.error("Parent did not confirm id mapping write")
                os._exit(1)

    if flags & CLONE_NEWPID:
        # Fork again so the grandchild becomes PID 1 in the new PID namespace.
        # Create a pipe to synchronize the launcher with the grandchild's readiness.
        sync_r, sync_w = os.pipe()

        grandchild_pid = os.fork()
        if grandchild_pid > 0:
            # Launcher:
            os.close(sync_w)
            # Wait for the grandchild to complete its setup and signal readiness.
            try:
                ready_signal = os.read(sync_r, 1)
            except OSError:
                ready_signal = b""
            finally:
                os.close(sync_r)

            if ready_signal == b"K":
                # Grandchild is ready. Send its host PID to the parent.
                with contextlib.suppress(OSError):
                    os.write(pid_w, str(grandchild_pid).encode())
            os.close(pid_w)

            # Wait for the grandchild to exit (it won't, unless killed).
            with contextlib.suppress(ChildProcessError):
                os.waitpid(grandchild_pid, 0)
            os._exit(0)

        # Grandchild - this is the actual holder (PID 1).
        os.close(sync_r)
        os.close(pid_w)
        _run_holder(sync_w, rootfs)
    else:
        # No PID namespace - the launcher itself is the holder.
        _run_holder(pid_w, rootfs)

    # Should never be reached.
    os._exit(1)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_holder(notify_fd: int, rootfs: str | None) -> None:
    """Execute the holder loop: set propagation, chroot, signal, sleep.

    This function never returns - it either sleeps forever or calls
    ``os._exit``.

    Args:
        notify_fd: File descriptor to write the readiness byte to.
        rootfs: Optional root filesystem to ``chroot`` into.
    """
    # 1. Set mount propagation to private.
    with contextlib.suppress(OSError):
        libc_mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

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
    except (KeyboardInterrupt, SystemExit) as exc:
        log.debug("Holder process interrupted: %s", exc)
    os._exit(0)


def _reap_child(pid: int) -> None:
    """Wait for *pid* without raising on unexpected statuses.

    Args:
        pid: The child PID to reap.
    """
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)
