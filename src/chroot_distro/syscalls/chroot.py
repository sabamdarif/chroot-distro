"""Native ``chroot(2)`` implementation replacing the GNU chroot binary.

This module provides two main entry points:

- :func:`native_chroot` — performs ``chroot`` + ``chdir`` + user/group
  switching + ``execvp`` in the **current process** (replaces it).
- :func:`chroot_and_exec` — forks first, performs the chroot+exec in the
  child, and returns the child's exit code to the parent.

Both are faithful ports of the behavior in GNU coreutils ``chroot.c``:
the order of ``setgroups`` → ``setgid`` → ``setuid`` exactly matches
the C implementation.
"""

from __future__ import annotations

import logging
import os
import signal
import sys

log = logging.getLogger(__name__)


def native_chroot(
    newroot: str,
    *,
    command: list[str] | None = None,
    uid: int | None = None,
    gid: int | None = None,
    groups: list[int] | None = None,
    skip_chdir: bool = False,
) -> None:
    """Change root to *newroot* and optionally exec *command*.

    This is a faithful port of GNU coreutils ``chroot.c``:

    1. ``chroot(newroot)``
    2. ``chdir("/")`` — unless *skip_chdir* is True
    3. ``setgroups(groups)`` — if *groups* is provided
    4. ``setgid(gid)`` — if *gid* is provided
    5. ``setuid(uid)`` — if *uid* is provided
    6. ``os.execvp(command[0], command)`` — if *command* is provided

    .. note::

       If *command* is provided this function **does not return** (the
       current process image is replaced).  If *command* is ``None`` the
       function returns after setting up the chroot environment.

    Parameters
    ----------
    newroot:
        Path to the new root directory.
    command:
        Command to execute after chroot.  If ``None``, no exec is
        performed and the function returns.
    uid:
        User ID to switch to (via ``setuid``).
    gid:
        Group ID to switch to (via ``setgid``).
    groups:
        Supplementary group list (via ``setgroups``).
    skip_chdir:
        If True, do not ``chdir("/")`` after chroot.

    Raises
    ------
    OSError
        On any syscall failure.
    FileNotFoundError
        If *newroot* does not exist.
    """
    if not os.path.isdir(newroot):
        raise FileNotFoundError(f"chroot: cannot change root directory to '{newroot}': No such file or directory")

    os.chroot(newroot)

    if not skip_chdir:
        os.chdir("/")

    # User/group switching — order matches coreutils chroot.c exactly:
    # setgroups → setgid → setuid (must drop groups/gid before uid).
    if groups is not None:
        os.setgroups(groups)

    if gid is not None:
        os.setgid(gid)

    if uid is not None:
        os.setuid(uid)

    if command is not None:
        os.execvp(command[0], command)


def chroot_and_exec(
    rootfs: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    uid: int | None = None,
    gid: int | None = None,
    groups: list[int] | None = None,
    workdir: str = "/",
) -> int:
    """Fork, chroot into *rootfs*, and exec *command* in the child.

    Unlike :func:`native_chroot` which replaces the current process,
    this function forks first and returns the child's exit code.  The
    parent process is unaffected and can perform cleanup (session
    counter decrement, mount teardown, etc.).

    Parameters
    ----------
    rootfs:
        Path to the container's root filesystem.
    command:
        Command and arguments to execute inside the chroot.
    env:
        Environment variables for the child process.  If ``None``,
        the current environment is inherited.
    uid:
        User ID to switch to inside the chroot.
    gid:
        Group ID to switch to inside the chroot.
    groups:
        Supplementary group list.
    workdir:
        Working directory inside the chroot (default ``"/"``).

    Returns
    -------
    int
        The child's exit code (0–255).  If the child was killed by a
        signal, returns 128 + signal_number.
    """
    child_pid = os.fork()

    if child_pid == 0:
        # --- Child process ---
        try:
            # Replace environment if specified.
            if env is not None:
                os.environ.clear()
                os.environ.update(env)

            os.chroot(rootfs)
            os.chdir(workdir)

            # User/group switching — order: setgroups → setgid → setuid
            if groups is not None:
                os.setgroups(groups)
            if gid is not None:
                os.setgid(gid)
            if uid is not None:
                os.setuid(uid)

            os.execvp(command[0], command)
        except Exception as exc:
            # If anything fails in the child, write to stderr and exit.
            try:
                sys.stderr.write(f"chroot_and_exec: {exc}\n")
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(127)

    # --- Parent process ---
    return _wait_for_child(child_pid)


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
) -> "CompletedProcess":
    """Fork, chroot, exec command, and capture output.

    Similar to :func:`chroot_and_exec` but returns a
    :class:`subprocess.CompletedProcess` with captured stdout/stderr
    when *capture_output* is True.

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

    if capture_output:
        stdout_r, stdout_w = os.pipe()
        stderr_r, stderr_w = os.pipe()

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

            if env is not None:
                os.environ.clear()
                os.environ.update(env)

            os.chroot(rootfs)
            os.chdir(workdir)

            if groups is not None:
                os.setgroups(groups)
            if gid is not None:
                os.setgid(gid)
            if uid is not None:
                os.setuid(uid)

            os.execvp(command[0], command)
        except Exception as exc:
            try:
                sys.stderr.write(f"chroot_and_run: {exc}\n")
                sys.stderr.flush()
            except Exception:
                pass
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

    returncode = _wait_for_child(child_pid, timeout=timeout)

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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


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
    return 1  # Shouldn't happen, but be safe.


def _read_all(fd: int) -> bytes:
    """Read all data from file descriptor *fd*."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)
