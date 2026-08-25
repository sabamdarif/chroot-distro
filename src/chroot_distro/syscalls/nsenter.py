# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Join an existing process's namespaces with setns(2), in place of nsenter(1).

A namespace is joined by opening `/proc/<pid>/ns/<name>` and handing that
descriptor to setns(2). The whole of nsenter(1) this program needs is here, in
four shapes: `enter_namespaces` moves the current process, `enter_and_exec` and
`run_in_namespaces` fork and exec a command, and `call_in_namespaces` forks and
runs a *Python* callable, which is what most callers actually want, since the work
is a handful of syscalls and the only reason to leave this process was to be
somewhere else when they run.

The order matters, and one pass is not enough. Entering the mount or PID namespace
of a process inside a user namespace fails until the user namespace itself has been
joined, so `enter_namespaces` mirrors util-linux nsenter.c: pass 1 tries every
non-user namespace and swallows the failures, pass 2 enters what is left, user
namespace included, and raises. Every descriptor is opened before either pass, since
`/proc/<pid>/ns/*` stops being reachable the moment the caller changes namespace.

`call_in_namespaces` returns bytes down a pipe because *fn* runs in a forked copy:
nothing it does to memory reaches the parent. The parent reads to EOF before
reaping, or output larger than the pipe buffer leaves the child blocked in write(2)
and never waited for.

`filter_accessible_namespaces` exists so a caller can degrade instead of failing:
whether a namespace file can be opened depends on the kernel, its config and the
caller's privileges, not on a version number.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import typing

from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWTIME,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    NS_FILE_MAP,
)
from chroot_distro.syscalls._libc import py_setns
from chroot_distro.syscalls.capabilities import drop_bounding_caps

log = logging.getLogger(__name__)

# User namespace last, so de-privileging happens only after every other
# namespace has been entered.
_NS_ORDER: list[int] = [
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUTS,
    CLONE_NEWIPC,
    CLONE_NEWCGROUP,
    CLONE_NEWNET,
    CLONE_NEWTIME,
    CLONE_NEWUSER,
]


def _ns_path(pid: int, nstype: int) -> str:
    """Return the ``/proc/<pid>/ns/<name>`` path for *nstype*.

    Args:
        pid: Target process ID.
        nstype: One of the ``CLONE_NEW*`` constants.

    Returns:
        Absolute path to the namespace file.

    Raises:
        KeyError: If *nstype* is not in :data:`NS_FILE_MAP`.
    """
    return f"/proc/{pid}/ns/{NS_FILE_MAP[nstype]}"


def check_ns_accessible(pid: int, nstype: int) -> bool:
    """Return ``True`` if the namespace file for *nstype* can be opened.

    Attempts to open ``/proc/<pid>/ns/<name>`` with ``O_RDONLY``.  On
    success the file descriptor is closed immediately and ``True`` is
    returned.  On :class:`OSError` (e.g. ``EACCES``, ``ENOENT``) the
    function returns ``False``.

    Args:
        pid: Target process ID whose namespace to probe.
        nstype: A ``CLONE_NEW*`` constant identifying the namespace type.

    Returns:
        ``True`` if the namespace file is accessible, ``False`` otherwise.
    """
    path = _ns_path(pid, nstype)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        log.debug("namespace file not accessible: %s", path)
        return False
    os.close(fd)
    return True


def enter_namespaces(target_pid: int, namespaces: int) -> None:
    """Enter one or more namespaces of *target_pid*.

    For each bit set in *namespaces*, the corresponding
    ``/proc/<target_pid>/ns/<name>`` file is opened and passed to
    ``setns(2)``.

    A two-pass strategy (modeled on ``util-linux nsenter.c``) is used:

    * **Pass 1** attempts to enter every requested *non-user* namespace.
      Errors are suppressed because some namespaces (e.g. mount, PID)
      may require the caller to be inside the target user namespace
      first.
    * **Pass 2** enters any namespaces that were not joined in pass 1,
      including the user namespace.  Errors in this pass are fatal and
      result in an :class:`OSError`.

    All file descriptors are closed after use regardless of success or
    failure.

    Args:
        target_pid: PID of the process whose namespaces to enter.
        namespaces: Bitmask of ``CLONE_NEW*`` flags indicating which
            namespaces to join.

    Raises:
        OSError: If a namespace cannot be entered in pass 2.
    """
    requested: list[int] = [ns for ns in _NS_ORDER if namespaces & ns]
    fds: dict[int, int] = {}
    try:
        for nstype in requested:
            path = _ns_path(target_pid, nstype)
            fds[nstype] = os.open(path, os.O_RDONLY)

        entered: set[int] = set()

        for nstype in requested:
            if nstype == CLONE_NEWUSER:
                continue
            try:
                py_setns(fds[nstype], nstype)
                entered.add(nstype)
                log.debug(
                    "pass 1: entered %s namespace of pid %d",
                    NS_FILE_MAP[nstype],
                    target_pid,
                )
            except OSError as exc:
                log.debug(
                    "pass 1: deferred %s namespace of pid %d (%s)",
                    NS_FILE_MAP[nstype],
                    target_pid,
                    exc,
                )

        for nstype in requested:
            if nstype in entered:
                continue
            py_setns(fds[nstype], nstype)
            entered.add(nstype)
            log.debug(
                "pass 2: entered %s namespace of pid %d",
                NS_FILE_MAP[nstype],
                target_pid,
            )
    finally:
        for fd in fds.values():
            with contextlib.suppress(OSError):
                os.close(fd)


def enter_and_exec(
    target_pid: int,
    namespaces: int,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    fork_for_pid: bool = True,
) -> int:
    """Fork, enter namespaces, and ``execvpe`` a command.

    The function forks a child process that calls
    :func:`enter_namespaces` and then replaces itself with *command* via
    :func:`os.execvpe`.

    When *fork_for_pid* is ``True`` **and** :data:`CLONE_NEWPID` is among
    the requested namespaces, an additional fork is performed *after*
    entering namespaces.  This causes the ``exec``-ed process to see
    itself as PID 1 (or higher) inside the new PID namespace, which is
    the expected behavior for most container work-loads.

    The parent process waits for the (outer) child and returns its exit
    code.

    Args:
        target_pid: PID of the process whose namespaces to enter.
        namespaces: Bitmask of ``CLONE_NEW*`` flags.
        command: Command and arguments to execute (``argv``).
        env: Optional environment mapping.  Defaults to :data:`os.environ`.
        fork_for_pid: Whether to double-fork when a PID namespace is
            requested.  Defaults to ``True``.

    Returns:
        Exit code of the executed command (0-255).

    Raises:
        OSError: If forking or entering namespaces fails.
    """
    child_pid = os.fork()
    if child_pid == 0:
        # --- child ---
        try:
            enter_namespaces(target_pid, namespaces)

            if fork_for_pid and (namespaces & CLONE_NEWPID):
                # Double-fork so the exec'd process is PID >1 in the
                # new PID namespace.
                inner_pid = os.fork()
                if inner_pid != 0:
                    # Middle process, whose only job is the exit code.
                    _, status = os.waitpid(inner_pid, 0)
                    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))

            os.execvpe(command[0], command, env if env is not None else os.environ)
        except BaseException:
            os._exit(127)
    else:
        # --- parent ---
        _, status = os.waitpid(child_pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        return 128 + os.WTERMSIG(status)


def run_in_namespaces(
    target_pid: int,
    namespaces: int,
    command: list[str],
    *,
    capture_output: bool = False,
    text: bool = False,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Enter namespaces and run a command, returning a :class:`~subprocess.CompletedProcess`.

    The function forks a child process that enters the target namespaces
    and ``exec``-s *command*.  When *capture_output* is ``True``, pipes
    are set up for ``stdout`` and ``stderr`` and their contents are
    collected in the parent.

    Args:
        target_pid: PID of the process whose namespaces to enter.
        namespaces: Bitmask of ``CLONE_NEW*`` flags.
        command: Command and arguments to execute (``argv``).
        capture_output: If ``True``, capture stdout and stderr via
            pipes.
        text: If ``True``, decode captured stdout/stderr as UTF-8 with
            ``errors='replace'``.
        timeout: Optional timeout in seconds.  If the child has not
            exited within *timeout* seconds, it is sent ``SIGKILL`` and
            :class:`subprocess.TimeoutExpired` is raised.
        env: Optional environment mapping.  Defaults to :data:`os.environ`.

    Returns:
        A :class:`subprocess.CompletedProcess` instance whose
        :attr:`~subprocess.CompletedProcess.args` is *command* and whose
        :attr:`~subprocess.CompletedProcess.returncode` is the child's
        exit status.

    Raises:
        subprocess.TimeoutExpired: If *timeout* is exceeded.
        OSError: If forking or pipe creation fails.
    """
    stdout_r: int | None = None
    stdout_w: int | None = None
    stderr_r: int | None = None
    stderr_w: int | None = None

    if capture_output:
        stdout_r, stdout_w = os.pipe()
        stderr_r, stderr_w = os.pipe()

    child_pid = os.fork()

    if child_pid == 0:
        # --- child ---
        try:
            if capture_output:
                assert stdout_w is not None
                assert stderr_w is not None
                os.dup2(stdout_w, 1)
                os.dup2(stderr_w, 2)
                for fd in (stdout_r, stdout_w, stderr_r, stderr_w):
                    if fd is not None:
                        with contextlib.suppress(OSError):
                            os.close(fd)

            enter_namespaces(target_pid, namespaces)
            os.execvpe(command[0], command, env if env is not None else os.environ)
        except BaseException:
            os._exit(127)
    else:
        # --- parent ---
        # The parent's write ends have to go, or the reads below never see
        # EOF when the child exits.
        if capture_output:
            assert stdout_w is not None
            assert stderr_w is not None
            os.close(stdout_w)
            os.close(stderr_w)

        stdout_data: bytes | str | None = None
        stderr_data: bytes | str | None = None

        _timed_out = False
        old_handler = None

        try:
            if timeout is not None:

                def _alarm_handler(signum: int, frame: object) -> None:
                    nonlocal _timed_out
                    _timed_out = True

                old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
                signal.alarm(timeout)

            if capture_output:
                assert stdout_r is not None
                assert stderr_r is not None
                # One pipe is drained before the other: the child can write to
                # both at once, but the kernel buffers what is not read yet.
                stdout_chunks: list[bytes] = []
                stderr_chunks: list[bytes] = []
                with open(stdout_r, "rb", closefd=True) as f_out:
                    # The file object owns the fd now; the finally below must
                    # not close it a second time.
                    stdout_r = None
                    stdout_chunks.append(f_out.read())
                with open(stderr_r, "rb", closefd=True) as f_err:
                    stderr_r = None
                    stderr_chunks.append(f_err.read())

                raw_stdout = b"".join(stdout_chunks)
                raw_stderr = b"".join(stderr_chunks)

                if text:
                    stdout_data = raw_stdout.decode("utf-8", errors="replace")
                    stderr_data = raw_stderr.decode("utf-8", errors="replace")
                else:
                    stdout_data = raw_stdout
                    stderr_data = raw_stderr

            _, status = os.waitpid(child_pid, 0)

            if timeout is not None and old_handler is not None:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
                if _timed_out:
                    # SIGALRM normally interrupts waitpid, so getting here
                    # means the alarm fired first and the child is still up.
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                        os.waitpid(child_pid, 0)
                    except OSError as exc:
                        log.debug("Failed to kill or wait for timed out child process %s: %s", child_pid, exc)
                    raise subprocess.TimeoutExpired(command, float(timeout))

            returncode = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)

        except InterruptedError:
            try:
                os.kill(child_pid, signal.SIGKILL)
                os.waitpid(child_pid, 0)
            except OSError as exc:
                log.debug("Failed to kill or wait for child process %s on interrupt: %s", child_pid, exc)
            if timeout is not None and old_handler is not None:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            raise subprocess.TimeoutExpired(command, float(timeout or 0)) from None

        finally:
            for fd in (stdout_r, stderr_r):
                if fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(fd)

        return subprocess.CompletedProcess(
            args=command,
            returncode=returncode,
            stdout=stdout_data,
            stderr=stderr_data,
        )


def call_in_namespaces(
    target_pid: int,
    namespaces: int,
    fn: typing.Callable[[], bytes | None],
) -> bytes | None:
    """Run *fn* inside *target_pid*'s namespaces and return what it produced.

    This is what a coreutils argv was standing in for: the work is a few
    syscalls, and the only reason to leave this process was to be in another
    namespace when they run. A fork plus setns(2) gets that, so *fn* is
    ordinary Python and its bytes come back down a pipe. ``None`` means the
    child raised or died, which the caller reads as failure.

    *fn* runs in a forked copy of this process. Nothing it does to memory
    reaches the parent, so anything it has to say belongs in its return value.
    """
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()

    if child_pid == 0:
        # --- Child ---
        try:
            os.close(read_fd)
            enter_namespaces(target_pid, namespaces)
            data = fn()
            if data:
                os.write(write_fd, data)
            os.close(write_fd)
            os._exit(0)
        except BaseException:
            os._exit(1)

    # --- Parent ---
    # Read to EOF before reaping: fn's output can exceed the pipe buffer, and
    # a child blocked in write(2) would never be waited for.
    os.close(write_fd)
    try:
        chunks = []
        while True:
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        chunks = []
    finally:
        os.close(read_fd)

    _, status = os.waitpid(child_pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        return None
    return b"".join(chunks)


def filter_accessible_namespaces(pid: int, namespaces: int) -> int:
    """Return only the namespace bits whose ``/proc`` files are accessible.

    Iterates over each ``CLONE_NEW*`` bit set in *namespaces* and calls
    :func:`check_ns_accessible` for each.  Bits for which the namespace
    file cannot be opened are cleared.

    This is useful for gracefully degrading when certain namespace types
    are not available (e.g. ``CLONE_NEWTIME`` on older kernels or
    ``CLONE_NEWUSER`` in restricted environments).

    Args:
        pid: Target process ID.
        namespaces: Bitmask of ``CLONE_NEW*`` flags to test.

    Returns:
        A bitmask containing only the accessible namespace flags.
    """
    result = 0
    for nstype in _NS_ORDER:
        if namespaces & nstype and check_ns_accessible(pid, nstype):
            result |= nstype
    return result


def enter_and_run_with_pty(
    target_pid: int,
    namespaces: int,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    fork_for_pid: bool = True,
    drop_caps: bool = False,
    setup: typing.Callable[[], None] | None = None,
) -> int:
    """Enter namespaces via native ``setns(2)`` and exec *command* with a PTY.

    *setup* runs in the child once it is in the namespaces and has dropped what
    it is going to drop, immediately before the exec. It is how a caller puts
    the child somewhere this module knows nothing about (a chroot, an identity)
    without handing over an argv for a binary that would do it.

    When stdin is a terminal, allocates a fresh PTY pair so the child has
    its own controlling terminal (enabling job control, ``ttyname()``,
    ``tcsetpgrp()``, etc.).  The parent runs a raw-mode relay loop that
    forwards data between the original terminal and the PTY master.

    Falls back to a plain fork+exec when stdin is not a tty.

    This replaces the old pattern of building an ``nsenter`` binary argv
    and exec'ing it: everything is done via direct syscalls.

    Returns the child's exit code (0-255).
    """
    from chroot_distro.syscalls.chroot import (
        _copy_terminal_size,
        _pty_relay,
        _setup_child_pty,
        _try_exec,
        _wait_for_child_with_signals,
    )

    use_pty = os.isatty(0)
    master_fd = slave_fd = -1

    if use_pty:
        master_fd, slave_fd = os.openpty()
        _copy_terminal_size(0, master_fd)

    child_pid = os.fork()

    if child_pid == 0:
        # --- Child ---
        try:
            if use_pty:
                _setup_child_pty(master_fd, slave_fd)

            enter_namespaces(target_pid, namespaces)

            if fork_for_pid and (namespaces & CLONE_NEWPID):
                inner_pid = os.fork()
                if inner_pid != 0:
                    _, status = os.waitpid(inner_pid, 0)
                    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))

            # Drop dangerous capabilities when no user namespace is
            # providing capability scoping.
            if drop_caps:
                drop_bounding_caps()

            if setup is not None:
                setup()

            _try_exec(command, env if env is not None else dict(os.environ))
        except BaseException:
            os._exit(127)

    # --- Parent ---
    if use_pty:
        os.close(slave_fd)
        return _pty_relay(master_fd, child_pid)
    return _wait_for_child_with_signals(child_pid)
