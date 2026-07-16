import errno
import os
import struct
import subprocess
from unittest.mock import patch

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
        # second call (via interpreter) "succeeds" — just return

    with (
        patch("os.execvpe", side_effect=fake_execvpe),
        patch.object(chroot, "_binary_interpreter", return_value=str(interp)),
    ):
        chroot._try_exec([str(binary), "arg"], {})

    assert calls[0][0] == str(binary)
    assert calls[1][0] == str(interp)
    assert calls[1][1] == [str(interp), str(binary), "arg"]


# ── native_chroot: pre-syscall validation ───────────────────────────────────────
def test_native_chroot_missing_root_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        chroot.native_chroot(str(tmp_path / "does-not-exist"))


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
