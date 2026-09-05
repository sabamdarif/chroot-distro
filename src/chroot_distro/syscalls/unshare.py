# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Create namespaces with unshare(2), and hold them open.

unshare(2) has one rule that shapes everything here: it only puts *children* in a
new PID namespace, never the caller. So `create_holder_process` forks twice, which
is why it returns a `HolderPids` pair: the *holder* is the grandchild whose
namespaces are joined or killed, the *launcher* is this process's own child and
therefore the one to wait for. A child that becomes PID 1 also resets mount
propagation to MS_REC|MS_PRIVATE, or every mount made inside would propagate
straight back to the host namespace.

A holder exists because namespaces die with their last member. Given a *rootfs* it
chroots itself, which closes the `chroot /proc/1/root` escape a namespace whose PID
1 sits on the host root would leave open. It then sleeps forever, or, with a
`ForegroundExec`, execs the session's own command so that command *is* PID 1 and
the namespaces end when it does.

Two synchronisation channels are not optional. A pipe carries the holder's host PID
back out, since a PID inside a new namespace means nothing to the parent. And the
foreground exec waits for its own go byte, separate from the holder-wide readiness
byte, because the parent mounts into the namespace only after the holder is up and
the command has to see those mounts.

A user namespace needs a third: uid_map and gid_map can only be written from
outside, and the child must not proceed until they exist, so the parent writes them
and then sends `M`.

`probe_namespace_support` forks a throw-away child per bit rather than trusting a
kernel version, because whether a flag works depends on the kernel config, the
sysctls and the caller's own privileges.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import time
import typing

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


def probe_namespace_support(flags: int) -> int:
    """Test which ``CLONE_NEW*`` namespace flags the kernel supports.

    For **each** bit set in *flags* a throw-away child process is forked
    and attempts ``unshare(bit)``.  The child exits with status ``0`` on
    success or ``1`` on failure.  The parent collects the results and
    returns a bitmask of the flags that succeeded.

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
            try:
                py_unshare(bit)
            except OSError:
                os._exit(1)
            os._exit(0)

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
    at ``allow``, or the container's own ``login``/``su`` cannot call
    ``setgroups(2)`` to set supplementary groups (it fails with EPERM). An
    unprivileged parent must write ``deny`` for the gid_map write to succeed.
    """
    uid_map, gid_map = id_map if id_map is not None else _default_id_map()

    if os.getuid() != 0:
        try:
            with open(f"/proc/{child_pid}/setgroups", "w") as fh:
                fh.write("deny")
        except OSError:
            log.debug("Failed to write setgroups deny for pid %d (may not be required)", child_pid)

    with open(f"/proc/{child_pid}/uid_map", "w") as fh:
        fh.write(uid_map)

    with open(f"/proc/{child_pid}/gid_map", "w") as fh:
        fh.write(gid_map)


class HolderPids(typing.NamedTuple):
    """The two PIDs a holder is made of.

    *holder* keeps the namespaces open and is the one to join or kill.
    *launcher* is this process's own child, so it is the one to wait for; with
    a PID namespace the two differ, because unshare(2) only puts *children* in
    the new namespace and the holder therefore has to be a grandchild.
    """

    holder: int
    launcher: int


@dataclasses.dataclass(frozen=True)
class ForegroundExec:
    """What a holder becomes instead of sleeping forever.

    A holder that execs the session's own command is how the command gets to be
    PID 1 of the namespace it runs in, so the namespace dies with it. It has to
    wait to be told the mounts are up, which is what *go_fd* is for: the parent
    writes one byte there once it has finished the setup the command depends on.

    The chroot waits for that byte too, rather than being the holder-wide one
    :func:`create_holder_process` takes: the parent mounts into this namespace
    after the holder is up, and the command has to see those mounts.
    """

    go_fd: int
    rootfs: str
    command: list[str]
    env: dict[str, str] | None = None
    stdio_fd: int = -1
    stdio_master_fd: int = -1
    uid: int | None = None
    gid: int | None = None
    groups: list[int] | None = None
    workdir: str = "/"
    drop_caps: bool = False


def create_holder_process(
    flags: int,
    *,
    rootfs: str | None = None,
    ready_fd: int = -1,
    id_map: tuple[str, str] | None = None,
    foreground: ForegroundExec | None = None,
) -> HolderPids:
    """Create a long-lived process that holds namespaces open.

    The holder process calls ``unshare(2)`` with *flags*, optionally
    ``chroot``\\ s into *rootfs* for maximum isolation, and then sleeps
    forever.  Other processes can later join its namespaces via
    ``/proc/<pid>/ns/*``.

    With *foreground* the holder execs that command instead of sleeping, once
    the parent writes the go byte; see :class:`ForegroundExec`.

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
        foreground: When given, what the holder execs instead of sleeping.

    Returns:
        The holder's host PID and this process's own child's PID; see
        :class:`HolderPids`.

    Raises:
        OSError: If ``unshare(2)`` or ``fork(2)`` fails, or if the
            holder process exits before signalling readiness.
        RuntimeError: If the holder fails to start.
    """
    # Pipe to send the actual holder's host PID back to the parent.
    pid_r, pid_w = os.pipe()

    # A user namespace needs a second pipe for id-mapping synchronisation:
    # the parent writes 'M' after writing uid/gid maps, and the child waits
    # for it before proceeding.
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
            # The child unshares CLONE_NEWUSER and reports its PID, which
            # is what the mappings below are written against.
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

                try:
                    _write_id_mappings(child_pid, id_map)
                except OSError as exc:
                    log.warning("Failed to write id mappings for pid %d: %s", child_pid, exc)

                if map_w >= 0:
                    with contextlib.suppress(OSError):
                        os.write(map_w, b"M")
                    os.close(map_w)
                    map_w = -1

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

        if ready_fd >= 0:
            try:
                os.write(ready_fd, b"K")
            except OSError:
                log.exception("failed to write to caller ready_fd")

        return HolderPids(holder=holder_pid, launcher=launcher_pid)

    # ---- Launcher (child) process ----
    os.close(pid_r)
    if map_w >= 0:
        os.close(map_w)  # Child only reads map_r.

    try:
        py_unshare(flags)
    except OSError:
        if has_userns:
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
        # Fork again so the grandchild becomes PID 1 in the new PID
        # namespace; sync_r/sync_w carry its readiness signal back here.
        sync_r, sync_w = os.pipe()

        grandchild_pid = os.fork()
        if grandchild_pid > 0:
            # Launcher: only the holder is to hold the terminal open, or the
            # relay would never see the session end.
            if foreground is not None:
                for fd in (foreground.stdio_fd, foreground.stdio_master_fd):
                    if fd >= 0:
                        with contextlib.suppress(OSError):
                            os.close(fd)
            os.close(sync_w)
            try:
                ready_signal = os.read(sync_r, 1)
            except OSError:
                ready_signal = b""
            finally:
                os.close(sync_r)

            if ready_signal == b"K":
                with contextlib.suppress(OSError):
                    os.write(pid_w, str(grandchild_pid).encode())
            os.close(pid_w)

            # A sleeping holder only ever gets here by being killed; a
            # foreground one exits with the session's own status, and this
            # process is what the parent waits on.
            status = 0
            with contextlib.suppress(ChildProcessError):
                _, status = os.waitpid(grandchild_pid, 0)
            if os.WIFEXITED(status):
                os._exit(os.WEXITSTATUS(status))
            os._exit(128 + os.WTERMSIG(status) if os.WIFSIGNALED(status) else 1)

        # Grandchild - this is the actual holder (PID 1).
        os.close(sync_r)
        os.close(pid_w)
        _run_holder(sync_w, rootfs, foreground)
    else:
        # No PID namespace: the launcher itself is the holder.
        _run_holder(pid_w, rootfs, foreground)

    # Should never be reached.
    os._exit(1)


def _run_holder(notify_fd: int, rootfs: str | None, foreground: ForegroundExec | None = None) -> None:
    """Execute the holder loop: set propagation, chroot, signal, then wait.

    This function never returns - it sleeps forever, execs *foreground*'s
    command, or calls ``os._exit``.

    Args:
        notify_fd: File descriptor to write the readiness byte to.
        rootfs: Optional root filesystem to ``chroot`` into.
        foreground: What to exec once the parent gives the go-ahead, instead
            of sleeping.
    """
    with contextlib.suppress(OSError):
        libc_mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

    if rootfs is not None:
        try:
            os.chroot(rootfs)
            os.chdir("/")
        except OSError:
            log.exception("chroot into %s failed", rootfs)
            os._exit(1)

    try:
        os.write(notify_fd, b"K")
    except OSError:
        log.exception("failed to write readiness signal")
        os._exit(1)
    finally:
        os.close(notify_fd)

    if foreground is not None:
        _exec_foreground(foreground)

    # Sleeping forever is the point: the namespaces live as long as this
    # process does.
    log.debug("holder process %d entering sleep loop", os.getpid())
    try:
        while True:
            time.sleep(2147483647)
    except (KeyboardInterrupt, SystemExit) as exc:
        log.debug("Holder process interrupted: %s", exc)
    os._exit(0)


def _exec_foreground(fg: ForegroundExec) -> None:
    """Wait for the go byte, then become *fg*'s command. Never returns.

    Already inside the namespaces; what is left is the terminal, the root, the
    identity, and the exec.
    """
    from chroot_distro.syscalls.chroot import _setup_child_pty, _try_exec, enter_chroot

    try:
        go = os.read(fg.go_fd, 1)
    except OSError:
        go = b""
    finally:
        with contextlib.suppress(OSError):
            os.close(fg.go_fd)

    if go != b"\n":
        # The parent gave up on the setup this command depends on.
        os._exit(1)

    try:
        if fg.stdio_fd >= 0:
            _setup_child_pty(fg.stdio_master_fd, fg.stdio_fd)

        enter_chroot(
            fg.rootfs,
            uid=fg.uid,
            gid=fg.gid,
            groups=fg.groups,
            workdir=fg.workdir,
            drop_caps=fg.drop_caps,
        )

        _try_exec(fg.command, fg.env if fg.env is not None else dict(os.environ))
    except BaseException:
        os._exit(127)


def _reap_child(pid: int) -> None:
    """Wait for *pid* without raising on unexpected statuses.

    Args:
        pid: The child PID to reap.
    """
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)
