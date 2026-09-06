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
to perform it.

Nothing here is handed a command line to a helper binary: a caller describes a
chroot and this file enters it in the process it already has, which is what keeps
the `chroot /proc/1/root` escape closed and what lets a build step or an isolation
holder be forked the same way.

`spawn_detached` clears close-on-exec on `keep_fds` deliberately: a caller passing
a lock descriptor needs the flock to survive the exec, since that is what goes on
signalling that the session is alive.

`_try_exec` retries through the binary's own PT_INTERP when a direct execve fails
with ENOENT or EACCES on a binary that plainly exists. That is an Android/Termux
kernel quirk on the login path, not a missing file, and running the dynamic linker
explicitly sidesteps it.
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
import os
import select
import signal
import subprocess
import sys
import typing

from chroot_distro.syscalls.capabilities import drop_bounding_caps

log = logging.getLogger(__name__)

# ioctl request code to acquire a controlling terminal (standard on all Linux).
_TIOCSCTTY = 0x540E
# Terminal window-size ioctls.
_TIOCGWINSZ = 0x5413
_TIOCSWINSZ = 0x5414


def enter_chroot(
    rootfs: str,
    *,
    uid: int | None = None,
    gid: int | None = None,
    groups: list[int] | None = None,
    workdir: str = "/",
    drop_caps: bool = False,
) -> None:
    """Chroot into *rootfs* and take on the target identity, without exec'ing.

    The current process is left inside the new root, so the caller is a process
    that is about to exec or exit. The order is coreutils' own: chroot, chdir,
    then setgroups before setgid before setuid, because each of those can only
    be given up once. A capability drop belongs before them, while the process
    still has the privilege to make it.
    """
    os.chroot(rootfs)
    os.chdir(workdir)

    if drop_caps:
        drop_bounding_caps()

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
        If True, capture stdout and stderr via pipes.
    text:
        If True, decode stdout/stderr as UTF-8.
    timeout:
        Maximum seconds to wait for the child.  ``None`` means wait
        indefinitely.

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

            if env is not None:
                os.environ.clear()
                os.environ.update(env)

            # drop_caps drops the bounding set when no user namespace is
            # providing capability scoping.
            enter_chroot(
                rootfs,
                uid=uid,
                gid=gid,
                groups=groups,
                workdir=workdir,
                drop_caps=drop_caps,
            )

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
        returncode = _wait_for_child_with_signals(child_pid, timeout=timeout)
    elif use_pty:
        os.close(slave_fd)
        returncode = _pty_relay(master_fd, child_pid, timeout=timeout)
    else:
        returncode = _wait_for_child_with_signals(child_pid, timeout=timeout)

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


def _pty_relay(master_fd: int, child_pid: int, *, timeout: int | None = None) -> int:
    """Relay data between the original terminal and the PTY master.

    Sets stdin to raw mode so control characters (Ctrl-C, Ctrl-Z, etc.)
    are forwarded verbatim through the PTY to the child. Handles
    SIGWINCH to keep the child's terminal size in sync.

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

    def _relay_sig(signum: int, _frame: object) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child_pid, signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        with contextlib.suppress(OSError, ValueError):
            prev_handlers[sig] = signal.signal(sig, _relay_sig)

    old_attrs: list[int | list[bytes | int]] | None = None
    try:
        old_attrs = termios.tcgetattr(0)
        tty.setraw(0)
    except (termios.error, OSError):
        pass

    try:
        _pty_copy_loop(master_fd)
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

    try:
        _, status = os.waitpid(child_pid, 0)
        return _decode_status(status)
    except ChildProcessError:
        return 0


def _pty_copy_loop(master_fd: int) -> None:
    """Bidirectional copy between stdin/stdout and a PTY master fd."""
    fds = [0, master_fd]
    while fds:
        try:
            rfds, _, _ = select.select(fds, [], [])
        except (OSError, ValueError, InterruptedError):
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


def _wait_for_child_with_signals(pid: int, *, timeout: int | None = None) -> int:
    """Wait for *pid* while forwarding terminal signals to the child.

    Installs handlers for SIGINT, SIGTERM and SIGHUP that relay each
    signal to the child process.  On ``KeyboardInterrupt`` (or any
    exception that unwinds the wait), the child is sent SIGTERM and
    then SIGKILL after a brief grace period so it never gets orphaned.
    """
    received_signal: list[int] = []

    def _relay(signum: int, _frame: object) -> None:
        received_signal.append(signum)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signum)

    prev_handlers: dict[signal.Signals, signal._HANDLER] = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        with contextlib.suppress(OSError, ValueError):
            prev_handlers[sig] = signal.signal(sig, _relay)

    try:
        returncode = _wait_for_child(pid, timeout=timeout)
    except BaseException:
        # The parent is being torn down, so the child must not survive it.
        _kill_child(pid)
        raise
    finally:
        for sig, handler in prev_handlers.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, handler)

    if received_signal and returncode >= 128:
        return returncode

    return returncode


def _kill_child(pid: int) -> None:
    """Best-effort SIGTERM → wait → SIGKILL for *pid*."""
    import time

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


def _wait_for_child(pid: int, *, timeout: int | None = None) -> int:
    """Wait for *pid* to exit, returning its exit code.

    If the child was killed by a signal, returns ``128 + signum``.
    """
    if timeout is not None:
        import time

        deadline = time.monotonic() + timeout
        while True:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid != 0:
                return _decode_status(status)
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
                return _decode_status(status)
            time.sleep(0.01)

    _, status = os.waitpid(pid, 0)
    return _decode_status(status)


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
