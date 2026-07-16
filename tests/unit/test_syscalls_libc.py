from unittest.mock import MagicMock

import pytest

from chroot_distro.syscalls import _libc


def test_get_libc_is_cached():
    a = _libc.get_libc()
    b = _libc.get_libc()
    assert a is b


def test_check_syscall_raises_on_minus_one(monkeypatch):
    monkeypatch.setattr(_libc.ctypes, "get_errno", lambda: 13)  # EACCES
    with pytest.raises(OSError) as ei:
        _libc.check_syscall(-1, "myfunc")
    assert ei.value.errno == 13
    assert "myfunc" in str(ei.value)


def test_check_syscall_passes_on_success():
    assert _libc.check_syscall(0, "ok") is None
    assert _libc.check_syscall(5, "ok") is None


def _fake_libc(monkeypatch, ret=0):
    libc = MagicMock()
    libc.mount.return_value = ret
    libc.umount2.return_value = ret
    libc.sethostname.return_value = ret
    libc.prctl.return_value = ret
    monkeypatch.setattr(_libc, "get_libc", lambda: libc)
    monkeypatch.setattr(_libc.ctypes, "get_errno", lambda: 1)
    return libc


def test_libc_mount_forwards_args(monkeypatch):
    libc = _fake_libc(monkeypatch)
    _libc.libc_mount(b"src", b"/tgt", b"tmpfs", 0, b"mode=0755")
    args = libc.mount.call_args.args
    assert args[0] == b"src"
    assert args[1] == b"/tgt"
    assert args[2] == b"tmpfs"


def test_libc_mount_raises_on_failure(monkeypatch):
    _fake_libc(monkeypatch, ret=-1)
    with pytest.raises(OSError):
        _libc.libc_mount(None, b"/tgt", None, 0, None)


def test_libc_umount2_raises_on_failure(monkeypatch):
    _fake_libc(monkeypatch, ret=-1)
    with pytest.raises(OSError):
        _libc.libc_umount2(b"/tgt", 0)


def test_libc_sethostname_encodes(monkeypatch):
    libc = _fake_libc(monkeypatch)
    _libc.libc_sethostname("box")
    name_bytes, length = libc.sethostname.call_args.args
    assert name_bytes == b"box"
    assert length == 3


def test_libc_prctl_returns_raw_result(monkeypatch):
    libc = _fake_libc(monkeypatch, ret=0)
    assert _libc.libc_prctl(1, 2) == 0
    # prctl must be padded to option + 4 unsigned longs.
    assert len(libc.prctl.call_args.args) == 5
