# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Enter a chroot and become the target identity, in place of the chroot binary.

Three entry points, differing only in what the caller wants back.
`enter_chroot` acts on the *current* process, so the caller is one that is about
to exec or exit; `chroot_and_run` forks first and returns the child's exit code or
its captured output, leaving the parent free to decrement the session count and
tear the mounts down.
`spawn_detached` forks a child meant to outlive this process.

The order of the identity change is coreutils' own and is not negotiable:
chroot, chdir, then setgroups before setgid before setuid. Each of those can only
be given up once, so a uid dropped early leaves the groups behind for good. A
capability drop goes before all of them, while the process still has the privilege
to perform it. A caller that joined a mapped user namespace with setns(2)
re-asserts its ids between the chdir and the keyring (`regain_ids`): earlier and
the subordinate id cannot traverse the rootfs path, later and the dropped
bounding set has taken the CAP_SETUID the regain needs.

Nothing here is handed a command line to a helper binary: a caller describes a
chroot and this file enters it in the process it already has, which is what keeps
the `chroot /proc/1/root` escape closed and what lets a build step or an isolation
holder be forked the same way.

A guest also leaves the host's session keyring behind: `_join_session_keyring`
swaps it for a fresh one while the child is still privileged, so host secrets
root's keyring holds never reach the guest. Best-effort by design, since a
container that will not start is worse than one sharing a keyring. The seccomp
denylist (`syscalls/seccomp.py`) installs last, before the identity change:
it needs the privilege, and the keyring it denies must already be joined.

`spawn_detached` clears close-on-exec on `keep_fds` deliberately: a caller passing
a lock descriptor needs the flock to survive the exec, since that is what goes on
signalling that the session is alive. Everything else is closed before the exec:
a descriptor the child does not need is a way out of the rootfs (a holder's
go-pipe or PTY master still names a host file), so each forked child runs
`_close_fds_above` between its own setup and the exec.

`_try_exec` retries through the binary's own PT_INTERP when a direct execve fails
with ENOENT or EACCES on a binary that plainly exists. That is an Android/Termux
kernel quirk on the login path, not a missing file, and running the dynamic linker
explicitly sidesteps it.
"""

from __future__ import annotations

import contextlib
import ctypes
import fcntl
import functools
import logging
import os
import select
import signal
import subprocess
import sys
import time
import typing

from chroot_distro.syscalls._constants import PR_SET_NO_NEW_PRIVS
from chroot_distro.syscalls._libc import libc_prctl, syscall_libc
from chroot_distro.syscalls.capabilities import clear_ambient_caps, drop_bounding_caps
from chroot_distro.syscalls.seccomp import install_guest_filter

log = logging.getLogger(__name__)

# ioctl request code to acquire a controlling terminal (standard on all Linux).
_TIOCSCTTY = 0x540E
# Terminal window-size ioctls.
_TIOCGWINSZ = 0x5413
_TIOCSWINSZ = 0x5414

# close_range(2) is in the architecture-synchronised range (>= 424), so one
# number serves every arch, like idmap's.
__NR_CLOSE_RANGE = 436
# close_range takes unsigned ints; the whole table is 3..UINT_MAX.
_FD_MAX = 0xFFFFFFFF

# How long a child gets to react to a relayed signal before the caller's
# escalation (the session sweep) runs; matches kill.py's SIGTERM grace.
_ESCALATE_GRACE_SECS = 1.0
# Idle poll interval for the pty relay and the child waits.
_COPY_POLL_SECS = 0.2


@functools.lru_cache(maxsize=1)
def _close_range_available() -> bool:
    """Whether close_range(2) works here (Linux 5.9+, not old Android)."""
    import ctypes
    import errno

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    # Probe with an empty range above the stdio descriptors: [2,2] would
    # close fd 2 itself, and in a forked child that is the PTY the whole
    # session talks through.
    result = libc.syscall(__NR_CLOSE_RANGE, _FD_MAX, _FD_MAX, 0)
    return not (result == -1 and ctypes.get_errno() in (errno.ENOSYS, errno.EPERM))


def _close_fds_above(keep: typing.Iterable[int]) -> None:
    """Close every descriptor above 2 except those in *keep*.

    Runs in a forked child, before the guest setup: a descriptor the exec does
    not need still names a host file (the holder's go-pipe, a PTY master), and
    holding it across the exec is the breakout shape CVE-2024-21626 fixed in
    runc. close_range(2) does it in two calls; below 5.9 the fallbacks are a
    /proc/self/fd walk, and an fstat scan capped at 1024 for a kernel with no
    visible /proc, where the fd table beyond that is host policy, not this
    program's.
    """
    import ctypes

    kept = {fd for fd in keep if fd > 2}
    if _close_range_available():
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        bounds = [(3, _FD_MAX)]
        if kept:
            lo, hi = min(kept), max(kept)
            bounds = [(3, lo - 1), (hi + 1, _FD_MAX)]
        for first, last in bounds:
            if first <= last:
                with contextlib.suppress(OSError):
                    libc.syscall(__NR_CLOSE_RANGE, first, last, 0)
        return

    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        for fd in range(3, 1024):
            if fd in kept:
                continue
            try:
                os.fstat(fd)
            except OSError:
                continue
            with contextlib.suppress(OSError):
                os.close(fd)
        return

    for name in names:
        if not name.isdigit():
            continue
        fd = int(name)
        if fd > 2 and fd not in kept:
            with contextlib.suppress(OSError):
                os.close(fd)


# keyctl(2) per arch, from runc's vendored golang.org/x/sys zsysnum tables.
# The operation codes (KEYCTL_*) are arch-independent.
__NR_KEYCTL_BY_ARCH = {"x86_64": 250, "i686": 288, "arm": 311, "aarch64": 219, "riscv64": 219}
KEYCTL_JOIN_SESSION_KEYRING = 1

_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def should_set_no_new_privs() -> bool:
    """Return True when ``CD_NO_NEW_PRIVS=1`` asks for the prctl."""
    return os.environ.get("CD_NO_NEW_PRIVS", "").strip().lower() in _TRUTHY_ENV


def _set_no_new_privs() -> None:
    """Set PR_SET_NO_NEW_PRIVS so a guest setuid binary cannot elevate.

    Off by default on purpose: it breaks sudo, su and setuid ping inside the
    guest, and a distro-in-a-chroot that cannot run those is a support trap.
    """
    result = libc_prctl(PR_SET_NO_NEW_PRIVS, 1)
    if result != 0:
        log.debug("PR_SET_NO_NEW_PRIVS failed: %d", result)


def _join_session_keyring() -> None:
    """Leave the host's session keyring by joining a fresh one.

    Runs in the guest child while it still has the privilege to: keyctl(2) is
    unprivileged-safe, but the point is that the guest never sees the session
    keyring root carries, which can hold host secrets. Best-effort, because a
    keyring is a nicety and a kernel without keyctl support (old Android) must
    not refuse the container a start.
    """
    from chroot_distro.arch import get_device_cpu_arch

    nr = __NR_KEYCTL_BY_ARCH.get(get_device_cpu_arch())
    if nr is None:
        log.debug("no keyctl syscall number for arch, keeping inherited keyring")
        return
    libc = syscall_libc()
    try:
        result = libc.syscall(
            ctypes.c_long(nr),
            ctypes.c_int(KEYCTL_JOIN_SESSION_KEYRING),
            ctypes.c_char_p(f"_ses.{os.getpid()}".encode()),
        )
        if result == -1:
            raise OSError(ctypes.get_errno(), "keyctl(2)")
    except OSError as exc:
        log.debug("fresh session keyring unavailable, keeping inherited: %s", exc)


def enter_chroot(
    rootfs: str,
    *,
    uid: int | None = None,
    gid: int | None = None,
    groups: list[int] | None = None,
    workdir: str = "/",
    drop_caps: bool = False,
    no_new_privs: bool = False,
    regain_ids: bool = False,
) -> None:
    """Chroot into *rootfs* and take on the target identity, without exec'ing.

    The current process is left inside the new root, so the caller is a process
    that is about to exec or exit. The order is coreutils' own: chroot, chdir,
    then setgroups before setgid before setuid, because each of those can only
    be given up once. A capability drop belongs before them, while the process
    still has the privilege to make it, and so does the fresh session keyring.

    *regain_ids* is for a process that entered a mapped user namespace with
    setns(2): the re-assert happens after the chroot, because the mapped
    (subordinate) id cannot necessarily traverse the rootfs path (a 0700 or
    0750 $HOME prefix), and before the capability drop, because setresuid(2)
    back into the map's range needs CAP_SETUID. A process that created its own
    user namespace is already mapped and leaves this off.
    """
    os.chroot(rootfs)
    os.chdir(workdir)

    if regain_ids:
        from chroot_distro.syscalls.nsenter import _regain_mapped_root

        _regain_mapped_root()

    _join_session_keyring()

    if no_new_privs or should_set_no_new_privs():
        _set_no_new_privs()

    if drop_caps:
        drop_bounding_caps()
        clear_ambient_caps()

    install_guest_filter()

    if groups is not None:
        os.setgroups(groups)
    if gid is not None:
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)


def chroot_and_run(
    rootfs: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    uid: int | None = None,
    gid: int | None = None,
    groups: list[int] | None = None,
    workdir: str = "/",
    capture_output: bool = False,
    text: bool = False,
    timeout: int | None = None,
    drop_caps: bool = False,
    no_new_privs: bool = False,
    escalate: typing.Callable[[], None] | None = None,
) -> subprocess.CompletedProcess:
    """Fork, chroot, exec command, and capture output.

    Returns a :class:`subprocess.CompletedProcess` with captured
    stdout/stderr when *capture_output* is True.

    Parameters
    ----------
    rootfs:
        Path to the container's root filesystem.
    command:
        Command and arguments to execute inside the chroot.
    env:
        Environment variables for the child process.
    uid, gid, groups:
        User, group, and supplementary groups for the child.
    workdir:
        Working directory inside the chroot.
    capture_output:
        If True, capture stdout/stderr via pipes.
    text:
        If True, decode stdout/stderr as UTF-8.
    timeout:
        Maximum seconds to wait for the child.  ``None`` means wait
        indefinitely.
    escalate:
        Zero-argument callback run once when the child outlives a relayed
        signal by :data:`_ESCALATE_GRACE_SECS`, for a caller that can force
        the session down (the login's rootfs sweep).  ``None`` keeps the
        plain wait.

    Returns
    -------
    subprocess.CompletedProcess
        The result of the command execution.
    """
    import subprocess

    stdout_r = stdout_w = stderr_r = stderr_w = -1
    use_pty = not capture_output and os.isatty(0)
    master_fd = slave_fd = -1

    if capture_output:
        stdout_r, stdout_w = os.pipe()
        stderr_r, stderr_w = os.pipe()
    elif use_pty:
        master_fd, slave_fd = os.openpty()
        _copy_terminal_size(0, master_fd)

    child_pid = os.fork()

    if child_pid == 0:
        # --- Child process ---
        try:
            if capture_output:
                os.close(stdout_r)
                os.close(stderr_r)
                os.dup2(stdout_w, 1)
                os.dup2(stderr_w, 2)
                os.close(stdout_w)
                os.close(stderr_w)
            elif use_pty:
                _setup_child_pty(master_fd, slave_fd)

            _close_fds_above(())

            # drop_caps drops the bounding set when no user namespace is
            # providing capability scoping.
            enter_chroot(
                rootfs,
                uid=uid,
                gid=gid,
                groups=groups,
                workdir=workdir,
                drop_caps=drop_caps,
                no_new_privs=no_new_privs,
            )

            # The guest environment replaces this process's only after the
            # CD_* switches in enter_chroot have been read: the guest env
            # deliberately carries none of them.
            if env is not None:
                os.environ.clear()
                os.environ.update(env)

            _try_exec(command, dict(os.environ))
        except Exception as exc:
            try:
                sys.stderr.write(f"chroot_and_run: {exc}\n")
                sys.stderr.flush()
            except Exception as stderr_exc:
                log.debug("Failed to write chroot_and_run failure to stderr: %s", stderr_exc)
            os._exit(127)

    # --- Parent process ---
    stdout_data = b""
    stderr_data = b""

    if capture_output:
        os.close(stdout_w)
        os.close(stderr_w)
        stdout_data = _read_all(stdout_r)
        stderr_data = _read_all(stderr_r)
        os.close(stdout_r)
        os.close(stderr_r)
        returncode = _wait_for_child_with_signals(child_pid, timeout=timeout, escalate=escalate)
    elif use_pty:
        os.close(slave_fd)
        returncode = _pty_relay(master_fd, child_pid, timeout=timeout, escalate=escalate)
    else:
        returncode = _wait_for_child_with_signals(child_pid, timeout=timeout, escalate=escalate)

    if text:
        stdout_out: str | bytes = stdout_data.decode("utf-8", errors="replace")
        stderr_out: str | bytes = stderr_data.decode("utf-8", errors="replace")
    else:
        stdout_out = stdout_data
        stderr_out = stderr_data

    return subprocess.CompletedProcess(
        args=command,
        returncode=returncode,
        stdout=stdout_out if capture_output else None,
        stderr=stderr_out if capture_output else None,
    )


def spawn_detached(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    keep_fds: tuple[int, ...] = (),
    setup: typing.Callable[[], None] | None = None,
) -> int:
    """Fork and exec *command* in its own session, returning the child's PID.

    The parent does not wait: the child is meant to outlive this process. Its
    three standard descriptors are the ones given, *keep_fds* are handed over
    as well (their close-on-exec is cleared, which is what a caller passing a
    lock descriptor is after: the flock has to survive the exec to keep
    signalling that the session is alive), and *setup* runs last, between the
    fork and the exec, for whatever the child has to become first.

    Raises:
        OSError: if the fork fails. A failure after it is the child's, and
            surfaces as its exit status.
    """
    child_pid = os.fork()

    if child_pid == 0:
        # --- Child ---
        try:
            os.setsid()
            os.dup2(stdin_fd, 0)
            os.dup2(stdout_fd, 1)
            os.dup2(stderr_fd, 2)
            _close_fds_above(keep_fds)
            for fd in keep_fds:
                os.set_inheritable(fd, True)
            if setup is not None:
                setup()
            _try_exec(command, env if env is not None else dict(os.environ))
        except BaseException:
            os._exit(127)

    return child_pid


def _copy_terminal_size(src_fd: int, dst_fd: int) -> None:
    """Copy the terminal window size from *src_fd* to *dst_fd*."""
    with contextlib.suppress(OSError):
        winsize = fcntl.ioctl(src_fd, _TIOCGWINSZ, b"\x00" * 8)
        fcntl.ioctl(dst_fd, _TIOCSWINSZ, winsize)


def _setup_child_pty(master_fd: int, slave_fd: int) -> None:
    """Set up the child side of a PTY pair as the controlling terminal.

    Called in the forked child *before* chroot/exec:
    1. Close the master (parent keeps it), when this child inherited one.
    2. ``setsid()`` to become session leader.
    3. ``TIOCSCTTY`` on the slave to make it the controlling terminal.
    4. Dup the slave to stdin/stdout/stderr.
    """
    if master_fd >= 0:
        os.close(master_fd)
    os.setsid()
    with contextlib.suppress(OSError):
        fcntl.ioctl(slave_fd, _TIOCSCTTY, 0)
    os.dup2(slave_fd, 0)
    os.dup2(slave_fd, 1)
    os.dup2(slave_fd, 2)
    if slave_fd > 2:
        os.close(slave_fd)


class _StuckSignalEscalation:
    """Force a wait to end when the child outlives a relayed signal.

    killpg gives the child and its group their chance to die, but an
    interactive shell ignores SIGTERM and a GUI it launched may sit in a
    session of its own, out of the group, so the relayed signal alone cannot
    end the wait. Once the first signal's grace expires, *callback* (the
    caller's rootfs sweep) runs once, the child dies, and the wait returns.
    """

    def __init__(self, signals: list[float], callback: typing.Callable[[], None]) -> None:
        self.signals = signals
        self.callback = callback
        self.done = False

    def check(self) -> None:
        if self.done or not self.signals:
            return
        if time.monotonic() - self.signals[0] < _ESCALATE_GRACE_SECS:
            return
        self.done = True
        self.callback()


def _signal_child(child_pid: int, signum: int) -> None:
    """Signal a child's process group, or the child alone when it leads none.

    A pty child is a session leader, so its pid is its group id and the group
    signal reaches a foreground GUI session along with it. A child that never
    called setsid shares this process's group, and a pid can only lead the
    group named after it, so for that child killpg is an ESRCH and the signal
    would be dropped instead of relayed.
    """
    try:
        os.killpg(child_pid, signum)
    except ProcessLookupError:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child_pid, signum)


def _pty_relay(
    master_fd: int,
    child_pid: int,
    *,
    timeout: int | None = None,
    escalate: typing.Callable[[], None] | None = None,
) -> int:
    """Relay data between the original terminal and the PTY master.

    Sets stdin to raw mode so control characters (Ctrl-C, Ctrl-Z, etc.)
    are forwarded verbatim through the PTY to the child. Handles
    SIGWINCH to keep the child's terminal size in sync.

    *escalate* is the caller's force-exit: when a relayed signal leaves the
    child alive past the grace period, it runs once so the wait can end
    (see :class:`_StuckSignalEscalation`).

    Returns the child's exit code.
    """
    import termios
    import tty

    prev_winch: signal._HANDLER = signal.SIG_DFL

    def _on_winsize(_signum: int, _frame: object) -> None:
        _copy_terminal_size(0, master_fd)
        with contextlib.suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGWINCH)

    with contextlib.suppress(OSError, ValueError):
        prev_winch = signal.signal(signal.SIGWINCH, _on_winsize)

    prev_handlers: dict[signal.Signals, signal._HANDLER] = {}
    signal_times: list[float] = []
    escalation = (
        _StuckSignalEscalation(signal_times, escalate) if escalate is not None else None
    )

    def _relay_sig(signum: int, _frame: object) -> None:
        # Signal the child's whole process group, not just the child: a GUI
        # session (dbus-launch startxfce4) leaves xfce4-session as the child's
        # foreground child in the same group, and signalling the child alone
        # leaves the session running while the child waits on it, hanging the
        # exit. The child is a session leader, so its pid is its group id.
        signal_times.append(time.monotonic())
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child_pid, signum)

    def _on_tstp(_signum: int, _frame: object) -> None:
        # Suspend the child and stop ourselves, so Ctrl-Z works even in raw
        # mode (where the terminal never generates SIGTSTP for us). The
        # foreground process group of the child's pty gets the stop; we then
        # stop too, and the real shell's SIGCONT resumes us.
        with contextlib.suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGTSTP)
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGTSTP)

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        with contextlib.suppress(OSError, ValueError):
            prev_handlers[sig] = signal.signal(sig, _relay_sig)
    # SIGTSTP is handled, not relayed, so the suspend actually reaches us.
    with contextlib.suppress(OSError, ValueError):
        prev_handlers[signal.SIGTSTP] = signal.signal(signal.SIGTSTP, _on_tstp)

    old_attrs: list[int | list[bytes | int]] | None = None
    try:
        old_attrs = termios.tcgetattr(0)
        tty.setraw(0)
    except (termios.error, OSError):
        pass

    try:
        _pty_copy_loop(master_fd, child_pid, escalation=escalation)
    finally:
        if old_attrs is not None:
            with contextlib.suppress(termios.error, OSError):
                termios.tcsetattr(0, termios.TCSAFLUSH, old_attrs)
        with contextlib.suppress(OSError):
            os.close(master_fd)
        with contextlib.suppress(OSError, ValueError):
            signal.signal(signal.SIGWINCH, prev_winch)
        for s, h in prev_handlers.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(s, h)

    # The copy loop may already have reaped the child when it detected the
    # exit; a ChildProcessError here means exactly that, not a missing child.
    try:
        return _wait_for_child(child_pid, escalation=escalation)
    except ChildProcessError:
        return 0


def _pty_copy_loop(
    master_fd: int,
    child_pid: int,
    *,
    escalation: _StuckSignalEscalation | None = None,
) -> None:
    """Bidirectional copy between stdin/stdout and a PTY master fd.

    Exits when the master reaches EOF *or* when the child has exited and its
    pty has gone quiet. The child check matters because a GUI session
    (``dbus-launch startxfce4``) leaves the window-manager and panel processes
    holding the pty slave open after the login shell has exited: without it the
    relay would wait for an EOF that never comes, and the session could not be
    exited at all.

    The select never blocks indefinitely: an idle pty is polled every
    ``_COPY_POLL_SECS``, both so the child's death is noticed while its
    orphans hold the slave open and so *escalation* (a relayed signal the
    child outlived) gets its turn while the child is still alive.
    """
    fds = [0, master_fd]
    child_dead = False
    while fds:
        try:
            rfds, _, _ = select.select(fds, [], [], _COPY_POLL_SECS)
        except (OSError, ValueError, InterruptedError):
            break
        if not child_dead:
            try:
                wpid, _ = os.waitpid(child_pid, os.WNOHANG)
                if wpid == child_pid:
                    child_dead = True
                    # A dead child reads nothing more; keep relaying only the
                    # pty output that is still draining.
                    if 0 in fds:
                        fds.remove(0)
            except ChildProcessError:
                child_dead = True
                if 0 in fds:
                    fds.remove(0)
            if escalation is not None:
                escalation.check()
        elif not rfds:
            # Child is dead and the pty produced nothing this window: the
            # writers left are orphans, not the session. Stop relaying.
            break
        if 0 in rfds:
            try:
                data = os.read(0, 4096)
            except OSError:
                data = b""
            if not data:
                fds.remove(0)
            else:
                try:
                    os.write(master_fd, data)
                except OSError:
                    break
        if master_fd in rfds:
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                data = b""
            if not data:
                break
            try:
                os.write(1, data)
            except OSError:
                break


def _wait_for_child_with_signals(
    pid: int,
    *,
    timeout: int | None = None,
    escalate: typing.Callable[[], None] | None = None,
) -> int:
    """Wait for *pid* while forwarding terminal signals to the child.

    Installs handlers for SIGINT, SIGTERM and SIGHUP that relay each
    signal to the child's process group. When *escalate* is given and the
    child outlives the first relayed signal by ``_ESCALATE_GRACE_SECS``, the
    callback runs once: it is the caller's way of forcing the session down
    where the relayed signal did not (an interactive shell ignores SIGTERM,
    a GUI may sit in a session of its own), so the wait always ends.
    On ``KeyboardInterrupt`` (or any exception that unwinds the wait), the
    child is sent SIGTERM and then SIGKILL after a brief grace period so it
    never gets orphaned.
    """
    signal_times: list[float] = []

    def _relay(signum: int, _frame: object) -> None:
        signal_times.append(time.monotonic())
        # Signal the process group so a foreground GUI session the child
        # launched (xfce4-session et al.) is interrupted along with the child;
        # signalling only the child leaves it waiting on that session forever.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signum)

    prev_handlers: dict[signal.Signals, signal._HANDLER] = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        with contextlib.suppress(OSError, ValueError):
            prev_handlers[sig] = signal.signal(sig, _relay)

    escalation = (
        _StuckSignalEscalation(signal_times, escalate) if escalate is not None else None
    )
    try:
        returncode = _wait_for_child(pid, timeout=timeout, escalation=escalation)
    except BaseException:
        # The parent is being torn down, so the child must not survive it.
        _kill_child(pid)
        raise
    finally:
        for sig, handler in prev_handlers.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, handler)

    return returncode


def _kill_child(pid: int) -> None:
    """Best-effort SIGTERM → wait → SIGKILL for *pid*."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid != 0:
                return
        except ChildProcessError:
            return
        time.sleep(0.05)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)


def _wait_for_child(
    pid: int,
    *,
    timeout: int | None = None,
    escalation: _StuckSignalEscalation | None = None,
) -> int:
    """Wait for *pid* to exit, returning its exit code.

    Polls with WNOHANG instead of one blocking waitpid: Python retries a
    blocking wait straight through a signal handler (PEP 475), which would
    leave the escalation no chance to act between the signal and the
    child's death. If the child was killed by a signal, returns
    ``128 + signum``.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid != 0:
            return _decode_status(status)
        if escalation is not None:
            escalation.check()
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            return _decode_status(status)
        time.sleep(0.01 if deadline is not None else 0.05)


def _decode_status(status: int) -> int:
    """Decode a waitpid status into an exit code."""
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def _read_all(fd: int) -> bytes:
    """Read all data from file descriptor *fd*."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _read_pt_interp(data: bytes, is64: bool, endian: str) -> str | None:
    """Extract the PT_INTERP path from raw ELF *data*, or None."""
    import struct as _struct

    pt_interp = 3
    if is64:
        (e_phoff,) = _struct.unpack_from(endian + "Q", data, 32)
        e_phentsize, e_phnum = _struct.unpack_from(endian + "HH", data, 54)
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            (p_type,) = _struct.unpack_from(endian + "I", data, base)
            if p_type == pt_interp:
                (p_offset,) = _struct.unpack_from(endian + "Q", data, base + 8)
                (p_filesz,) = _struct.unpack_from(endian + "Q", data, base + 32)
                return data[p_offset : p_offset + p_filesz].rstrip(b"\x00").decode("ascii", "replace")
    else:
        (e_phoff,) = _struct.unpack_from(endian + "I", data, 28)
        e_phentsize, e_phnum = _struct.unpack_from(endian + "HH", data, 42)
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            (p_type,) = _struct.unpack_from(endian + "I", data, base)
            if p_type == pt_interp:
                (p_offset,) = _struct.unpack_from(endian + "I", data, base + 4)
                (p_filesz,) = _struct.unpack_from(endian + "I", data, base + 16)
                return data[p_offset : p_offset + p_filesz].rstrip(b"\x00").decode("ascii", "replace")
    return None


def _binary_interpreter(target: str) -> str | None:
    """Return *target*'s PT_INTERP (dynamic linker) path, or None.

    Best-effort: reads the ELF header and program headers. Used to run the
    shell via its interpreter explicitly when a direct execve fails with
    ENOENT despite the binary and interpreter both existing (a Termux/Android
    quirk on the chroot login path).
    """
    try:
        with open(target, "rb") as fh:
            head = fh.read(64)
            if head[:4] != b"\x7fELF":
                return None
            is64 = head[4] == 2
            endian = "<" if head[5] == 1 else ">"
            fh.seek(0)
            return _read_pt_interp(fh.read(), is64, endian)
    except OSError:
        return None


def _try_exec(cmd: list[str], run_env: dict[str, str]) -> None:
    """Attempt to exec *cmd*; on ENOENT or EACCES for an existing binary, retry via its
    ELF interpreter. Returns the final OSError (this never returns on success).

    A direct ``execve`` of a dynamically linked guest binary can fail with
    ENOENT or EACCES on some Termux/Android kernels even though the binary, its
    architecture and its PT_INTERP all exist inside the chroot. Re-running it
    as ``<interpreter> <binary> <args...>`` makes the dynamic linker load the
    program explicitly and sidesteps that failure.
    """
    import errno as _errno

    try:
        os.execvpe(cmd[0], cmd, run_env)
    except OSError as exc:
        if exc.errno not in (_errno.ENOENT, _errno.EACCES) or not os.path.exists(cmd[0]):
            raise
        interp = _binary_interpreter(cmd[0])
        if not interp or not os.path.exists(interp):
            raise
        os.execvpe(interp, [interp, *cmd], run_env)
