"""The descriptor walk that every mount target goes through.

The rootfs is untrusted input (a pulled layer, a local archive, a backup), so
a mount target must never be a joined name: a symlink on the path is the
host-write hole the walk refuses. These tests build real trees on disk and
exercise the walk and the verify helpers directly, without any mount(2).
"""

import os
import stat

import pytest

from chroot_distro.exceptions import MountError, MountRefusedError
from chroot_distro.helpers import mount_targets as mt


def test_guest_parts_refuses_outside_rootfs(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(MountRefusedError):
        mt.guest_parts(str(outside), str(tmp_path / "root" / "escape"))


def test_guest_parts_splits_components(tmp_path):
    root = tmp_path / "root"
    parts = mt.guest_parts(str(root), str(root / "dev" / "pts"))
    assert parts == ["dev", "pts"]


def test_resolve_refuses_symlink_component(tmp_path):
    root = tmp_path / "root"
    (root / "real").mkdir(parents=True)
    (root / "link").symlink_to("real")
    with pytest.raises(MountRefusedError):
        mt.resolve_mount_target(str(root), ["link", "x"], want="dir", create=True)


def test_resolve_refuses_symlink_leaf(tmp_path):
    root = tmp_path / "root"
    host_dir = tmp_path / "host"
    host_dir.mkdir()
    root.mkdir()
    (root / "proc").symlink_to(str(host_dir))
    with pytest.raises(MountRefusedError):
        mt.resolve_mount_target(str(root), ["proc"], want="any", create=True)
    with pytest.raises(MountRefusedError):
        mt.resolve_mount_target(str(root), ["proc"], want="dir", create=False)


def test_resolve_refuses_file_where_dir_wanted(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "plain").write_text("x")
    with pytest.raises(MountRefusedError):
        mt.resolve_mount_target(str(root), ["plain", "child"], want="dir", create=False)


def test_resolve_missing_returns_none_when_not_creating(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    assert mt.resolve_mount_target(str(root), ["dev", "pts"], want="dir", create=False) is None


def test_resolve_creates_directories(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    fd = mt.resolve_mount_target(str(root), ["dev", "pts"], want="dir", create=True)
    try:
        assert (root / "dev" / "pts").is_dir()
    finally:
        os.close(fd)


def test_resolve_creates_file_stub_for_any(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    created: list[list[str]] = []
    fd = mt.resolve_mount_target(str(root), ["etc", "resolv.conf"], want="any", create=True, created=created)
    try:
        assert (root / "etc" / "resolv.conf").is_file()
        assert created == [["etc", "resolv.conf"]]
    finally:
        os.close(fd)


def test_resolve_file_refuses_symlink_and_nonregular(tmp_path):
    root = tmp_path / "root"
    (root / "dev").mkdir(parents=True)
    (root / "dev" / "null").symlink_to("/dev/null")
    with pytest.raises(MountRefusedError):
        mt.resolve_mount_target(str(root), ["dev", "null"], want="file", create=False)


def test_verify_dev_null_rejects_planted_file(tmp_path):
    planted = tmp_path / "null"
    planted.write_text("not a device")
    fd = os.open(planted, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        assert mt.verify_dev_null(fd) is False
    finally:
        os.close(fd)


def test_verify_dev_node_rejects_wrong_type_and_numbers(tmp_path):
    wrong = tmp_path / "wrong"
    wrong.write_text("x")
    fd = os.open(wrong, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        assert mt.verify_dev_node(fd, 1, 3) is False
    finally:
        os.close(fd)
    # mknod needs privileges, so the real char 1:3 device is the positive case
    fd = os.open("/dev/null", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        assert mt.verify_dev_node(fd, 1, 3) is True
        assert mt.verify_dev_node(fd, 1, 5) is False
    finally:
        os.close(fd)


def test_unlink_mount_target_removes_stub(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    created: list[list[str]] = []
    fd = mt.resolve_mount_target(str(root), ["a", "b", "stub"], want="any", create=True, created=created)
    os.close(fd)
    mt.unlink_mount_target(str(root), created[0])
    assert not (root / "a" / "b" / "stub").exists()
    # the made parents stay; only the leaf is rolled back
    assert (root / "a" / "b").is_dir()


def test_unlink_mount_target_will_not_follow_a_swapped_name(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    victim = root / "victim"
    victim.write_text("keep me")
    # someone swaps the stub name for a symlink to the victim; unlink removes
    # the link itself, and the victim stays untouched
    (root / "stub").symlink_to(str(victim))
    mt.unlink_mount_target(str(root), ["stub"])
    assert victim.exists()
    assert not (root / "stub").exists()


def test_open_ptmx_rejects_a_planted_node(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "dev" / "pts").mkdir(parents=True)
    # A planted stand-in: not a device at all, since mknod needs root.
    (root / "dev" / "pts" / "ptmx").write_text("fake")
    fd = os.open(root / "dev" / "pts" / "ptmx", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        assert mt.verify_dev_node(fd, 5, 2) is False
    finally:
        os.close(fd)


def test_open_ptmx_rejects_a_symlinked_pts(tmp_path):
    root = tmp_path / "root"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "dev").mkdir(parents=True)
    (root / "dev" / "pts").symlink_to(str(elsewhere))
    assert mt.open_ptmx(str(root)) is None
