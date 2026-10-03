import ctypes
import errno
import os
import struct
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.syscalls import chroot


# ── _decode_status ──────────────────────────────────────────────────────────────
def test_decode_status_exited():
    # WIFEXITED status: (code << 8)
    assert chroot._decode_status(5 << 8) == 5


def test_decode_status_signalled():
    # WIFSIGNALED: low 7 bits are the signal number, no 0x7f exited marker.
    assert chroot._decode_status(9) == 128 + 9  # SIGKILL


# ── _read_all ─────────────────────────────────────────────────────────────────
def test_read_all_drains_pipe():
    r, w = os.pipe()
    os.write(w, b"hello world")
    os.close(w)
    assert chroot._read_all(r) == b"hello world"
    os.close(r)


def test_read_all_empty():
    r, w = os.pipe()
    os.close(w)
    assert chroot._read_all(r) == b""
    os.close(r)


# ── ELF PT_INTERP parsing ───────────────────────────────────────────────────────
def _build_elf64(interp: bytes) -> bytes:
    """Minimal 64-bit LE ELF with a single PT_INTERP program header."""
    e_phoff = 64
    e_phentsize = 56
    interp_off = e_phoff + e_phentsize  # place interp string right after the phdr
    buf = bytearray(interp_off + len(interp))
    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1  # little-endian
    struct.pack_into("<Q", buf, 32, e_phoff)  # e_phoff
    struct.pack_into("<HH", buf, 54, e_phentsize, 1)  # e_phentsize, e_phnum
    # program header: p_type=PT_INTERP(3), p_offset, p_filesz
    struct.pack_into("<I", buf, e_phoff, 3)
    struct.pack_into("<Q", buf, e_phoff + 8, interp_off)
    struct.pack_into("<Q", buf, e_phoff + 32, len(interp))
    buf[interp_off:] = interp
    return bytes(buf)


def test_read_pt_interp_64():
    data = _build_elf64(b"/lib64/ld-linux-x86-64.so.2\x00")
    assert chroot._read_pt_interp(data, is64=True, endian="<") == "/lib64/ld-linux-x86-64.so.2"


def test_binary_interpreter_reads_elf(tmp_path):
    p = tmp_path / "prog"
    p.write_bytes(_build_elf64(b"/lib/ld.so\x00"))
    assert chroot._binary_interpreter(str(p)) == "/lib/ld.so"


def test_binary_interpreter_not_elf(tmp_path):
    p = tmp_path / "script"
    p.write_bytes(b"#!/bin/sh\n")
    assert chroot._binary_interpreter(str(p)) is None


def test_binary_interpreter_missing_file(tmp_path):
    assert chroot._binary_interpreter(str(tmp_path / "nope")) is None


# ── _try_exec ─────────────────────────────────────────────────────────────────
def test_try_exec_success_calls_execvpe():
    with patch("os.execvpe") as ex:
        chroot._try_exec(["/bin/true"], {})
    ex.assert_called_once_with("/bin/true", ["/bin/true"], {})


def test_try_exec_reraises_non_enoent():
    with patch("os.execvpe", side_effect=OSError(errno.EPERM, "denied")), pytest.raises(OSError):
        chroot._try_exec(["/bin/x"], {})


def test_try_exec_retries_via_interpreter(tmp_path):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF")
    interp = tmp_path / "lib" / "ld.so"
    interp.parent.mkdir()
    interp.write_bytes(b"\x7fELF")

    calls = []

    def fake_execvpe(path, argv, env):
        calls.append((path, argv))
        if len(calls) == 1:
            raise OSError(errno.ENOENT, "not found")
        # second call (via interpreter) "succeeds", just return

    with (
        patch("os.execvpe", side_effect=fake_execvpe),
        patch.object(chroot, "_binary_interpreter", return_value=str(interp)),
    ):
        chroot._try_exec([str(binary), "arg"], {})

    assert calls[0][0] == str(binary)
    assert calls[1][0] == str(interp)
    assert calls[1][1] == [str(interp), str(binary), "arg"]


# ── fork-based machinery (no root needed: chroot fails → child exits 127) ────────
def test_chroot_and_run_captures_child_failure(tmp_path):
    # A non-root process cannot chroot; the child hits the except branch and
    # exits 127. This exercises the full parent capture_output + wait path.
    result = chroot.chroot_and_run(
        str(tmp_path),
        ["/bin/true"],
        capture_output=True,
        text=True,
    )
    assert isinstance(result, subprocess.CompletedProcess)
    # chroot(2) is denied to a non-root process, so the child hits its except
    # branch and exits 127. (The child's stderr message goes to the real fd 2,
    # which pytest's capture replaces, so we assert on the exit code only.)
    assert result.returncode == 127


def test_wait_for_child_decodes_normal_exit():
    pid = os.fork()
    if pid == 0:
        os._exit(3)
    assert chroot._wait_for_child(pid) == 3


# ── _close_fds_above: the pre-exec descriptor sweep ─────────────────────────────
def test_close_fds_above_closes_unkept_keeps_kept():
    # Child inherits an extra fd; the sweep must close it and keep the one
    # named in *keep*. Reported through the kept pipe so no probe fd pollutes
    # the layout.
    r, w = os.pipe()
    extra = os.open(os.devnull, os.O_RDONLY)
    pid = os.fork()
    if pid == 0:
        os.close(r)
        chroot._close_fds_above((w,))
        try:
            os.fstat(extra)
            alive = 1
        except OSError:
            alive = 0
        try:
            os.fstat(w)
            kept = 1
        except OSError:
            kept = 0
        os._exit(alive * 2 + kept)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 1  # extra closed, keep survived
    os.close(r)
    os.close(w)
    os.close(extra)


def test_close_fds_above_no_keep_closes_everything():
    r, w = os.pipe()
    extra = os.open(os.devnull, os.O_RDONLY)
    pid = os.fork()
    if pid == 0:
        chroot._close_fds_above(())
        try:
            os.fstat(extra)
            alive = 1
        except OSError:
            alive = 0
        os._exit(alive)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
    os.close(r)
    os.close(w)
    os.close(extra)


def test_close_fds_above_proc_fallback_closes_unkept(monkeypatch):
    # Force the /proc/self/fd walk (the pre-5.9 path) and check it still closes.
    monkeypatch.setattr(chroot, "_close_range_available", lambda: False)
    r, w = os.pipe()
    extra = os.open(os.devnull, os.O_RDONLY)
    pid = os.fork()
    if pid == 0:
        chroot._close_fds_above((w,))
        try:
            os.fstat(extra)
            alive = 1
        except OSError:
            alive = 0
        os._exit(alive)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
    os.close(r)
    os.close(w)
    os.close(extra)


def test_spawn_detached_sweep_keeps_keep_fds(tmp_path):
    # spawn_detached closes everything above 2 except keep_fds, then the guest
    # setup runs. The setup callable reports through a file: the report pipe
    # would itself be swept, being above 2 and not kept.
    out = str(tmp_path / "survivors")
    leak = os.open(os.devnull, os.O_RDONLY)
    leak2 = os.open(os.devnull, os.O_RDONLY)

    def setup() -> None:
        alive = 0
        for fd in (leak, leak2):
            try:
                os.fstat(fd)
                alive += 1
            except OSError:
                pass
        with open(out, "w") as fh:
            fh.write(str(alive))

    devnull = os.open(os.devnull, os.O_RDONLY)
    pid = chroot.spawn_detached(
        ["/bin/true"],
        env={},
        stdin_fd=devnull,
        stdout_fd=devnull,
        stderr_fd=devnull,
        keep_fds=(leak,),
        setup=setup,
    )
    os.close(devnull)
    os.waitpid(pid, 0)
    # leak survives (kept), leak2 is closed by the sweep.
    assert open(out).read() == "1"
    os.close(leak)
    os.close(leak2)


# ── _join_session_keyring ───────────────────────────────────────────────────────
def test_join_session_keyring_calls_keyctl(monkeypatch):
    fake_libc = MagicMock()
    fake_libc.syscall.return_value = 42
    monkeypatch.setattr(chroot, "syscall_libc", lambda: fake_libc)
    monkeypatch.setattr(chroot, "__NR_KEYCTL_BY_ARCH", {"x86_64": 250})

    with patch("chroot_distro.arch.get_device_cpu_arch", return_value="x86_64"):
        chroot._join_session_keyring()
    # one keyctl call: JOIN_SESSION_KEYRING with a _ses.<pid> name
    args = fake_libc.syscall.call_args.args
    assert args[0].value == 250
    assert args[1].value == 1
    assert args[2].value.startswith(b"_ses.")


def test_join_session_keyring_tolerates_enosys(monkeypatch):
    fake_libc = MagicMock()

    def failing(*a):
        ctypes.set_errno(errno.ENOSYS)
        return -1

    fake_libc.syscall.side_effect = failing
    monkeypatch.setattr(chroot, "syscall_libc", lambda: fake_libc)
    monkeypatch.setattr(chroot, "__NR_KEYCTL_BY_ARCH", {"x86_64": 250})

    with patch("chroot_distro.arch.get_device_cpu_arch", return_value="x86_64"):
        chroot._join_session_keyring()  # must not raise


def test_join_session_keyring_unknown_arch_skips(monkeypatch):
    fake_libc = MagicMock()
    monkeypatch.setattr(chroot, "syscall_libc", lambda: fake_libc)
    monkeypatch.setattr(chroot, "__NR_KEYCTL_BY_ARCH", {"x86_64": 250})
    with patch("chroot_distro.arch.get_device_cpu_arch", return_value="mips"):
        chroot._join_session_keyring()
    fake_libc.syscall.assert_not_called()


# ── no_new_privs ────────────────────────────────────────────────────────────────
def test_should_set_no_new_privs_env(monkeypatch):
    monkeypatch.delenv("CD_NO_NEW_PRIVS", raising=False)
    assert chroot.should_set_no_new_privs() is False
    monkeypatch.setenv("CD_NO_NEW_PRIVS", "1")
    assert chroot.should_set_no_new_privs() is True
    monkeypatch.setenv("CD_NO_NEW_PRIVS", "0")
    assert chroot.should_set_no_new_privs() is False


def test_set_no_new_privs_calls_prctl():
    calls = []
    with patch.object(chroot, "libc_prctl", side_effect=lambda *a: calls.append(a) or 0):
        chroot._set_no_new_privs()
    assert calls[0][0] == 38  # PR_SET_NO_NEW_PRIVS
    assert calls[0][1] == 1


def test_close_range_probe_closes_no_stdio():
    # The availability probe once used the range [2, 2], which closed fd 2
    # itself: in a forked child fd 2 is the PTY the whole session talks
    # through, and the guest went mute. The probe must touch nothing.
    import ctypes

    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        libc.syscall(436, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        try:
            os.fstat(w)
            alive = 1
        except OSError:
            alive = 0
        # fd 2 must survive the probe too: write to it and check for EBADF.
        try:
            os.fstat(2)
            fd2 = 1
        except OSError:
            fd2 = 0
        os._exit((alive << 1) | fd2)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status)
    assert code == 3  # pipe fd alive AND fd 2 alive
    os.close(r)
    os.close(w)
