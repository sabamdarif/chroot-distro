import ctypes
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.syscalls import idmap


def _fake_libc(retval):
    """Return a libc mock whose syscall() returns *retval*."""
    libc = MagicMock()
    libc.syscall.return_value = retval
    return libc


# ── _check ────────────────────────────────────────────────────────────────────
def test_check_passes_through_nonneg():
    assert idmap._check(5, "x") == 5
    assert idmap._check(0, "x") == 0


def test_check_raises_on_minus_one():
    with patch("ctypes.get_errno", return_value=1), pytest.raises(OSError):
        idmap._check(-1, "open_tree")


# ── open_tree / move_mount / mount_setattr marshal args and check result ──────────
def test_open_tree_returns_fd():
    with patch.object(idmap, "_syscall_libc", return_value=_fake_libc(7)):
        assert idmap.open_tree(-100, "/mnt", idmap.OPEN_TREE_CLONE) == 7


def test_open_tree_raises_on_error():
    with (
        patch.object(idmap, "_syscall_libc", return_value=_fake_libc(-1)),
        patch("ctypes.get_errno", return_value=13),
        pytest.raises(OSError),
    ):
        idmap.open_tree(-100, "/mnt", 0)


def test_move_mount_ok():
    with patch.object(idmap, "_syscall_libc", return_value=_fake_libc(0)):
        idmap.move_mount(3, "", -100, "/dst", idmap.MOVE_MOUNT_F_EMPTY_PATH)  # no raise


def test_move_mount_raises():
    with (
        patch.object(idmap, "_syscall_libc", return_value=_fake_libc(-1)),
        patch("ctypes.get_errno", return_value=1),
        pytest.raises(OSError),
    ):
        idmap.move_mount(3, "", -100, "/dst", 0)


def test_mount_setattr_ok():
    attr = idmap.MountAttr(attr_set=idmap.MOUNT_ATTR_IDMAP, attr_clr=0, propagation=0, userns_fd=0)
    with patch.object(idmap, "_syscall_libc", return_value=_fake_libc(0)):
        idmap.mount_setattr(3, "", idmap.AT_EMPTY_PATH, attr)  # no raise


# ── MountAttr struct layout ──────────────────────────────────────────────────────
def test_mount_attr_struct_size():
    # Four u64 fields => 32 bytes; the kernel checks sizeof against this.
    assert ctypes.sizeof(idmap.MountAttr) == 32


# ── make_idmapped_tree: closes the tree fd and re-raises on setattr failure ───────
def test_make_idmapped_tree_closes_fd_on_setattr_error():
    with (
        patch.object(idmap, "open_tree", return_value=9),
        patch.object(idmap, "mount_setattr", side_effect=OSError(22, "EINVAL")),
        patch("os.close") as mock_close,
        pytest.raises(OSError),
    ):
        idmap.make_idmapped_tree("/src", userns_fd=4)
    mock_close.assert_called_once_with(9)


def test_make_idmapped_tree_success_returns_fd():
    with (
        patch.object(idmap, "open_tree", return_value=11),
        patch.object(idmap, "mount_setattr"),
    ):
        assert idmap.make_idmapped_tree("/src", userns_fd=4) == 11


def test_make_idmapped_tree_non_recursive_flags():
    # recursive=False must not set AT_RECURSIVE on the setattr call.
    captured = {}

    def fake_setattr(dfd, path, flags, attr):
        captured["flags"] = flags

    with (
        patch.object(idmap, "open_tree", return_value=11),
        patch.object(idmap, "mount_setattr", side_effect=fake_setattr),
    ):
        idmap.make_idmapped_tree("/src", userns_fd=4, recursive=False)
    assert not (captured["flags"] & idmap.AT_RECURSIVE)
