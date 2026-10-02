"""Tests for namespace-aware mount_manager helpers."""

import os
import stat
from unittest.mock import MagicMock, patch

from chroot_distro.helpers import mount_manager as mm


def test_get_active_mounts_via_holder():
    holder = MagicMock()
    holder.get_proc_mounts.return_value = (
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "tmpfs /tmp/rootfs/dev/shm tmpfs rw,nosuid,nodev,relatime 0 0\n"
    )
    rootfs = "/tmp/rootfs"
    with patch("os.path.realpath", side_effect=lambda p: p):
        mounts = mm.get_active_mounts(rootfs, holder=holder)
    assert "/tmp/rootfs/dev/shm" in mounts


def test_safe_mount_via_holder():
    # With a holder the walk and the mount run inside that namespace.
    holder = MagicMock()
    holder.call.side_effect = lambda fn: fn()

    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch.object(mm, "is_mounted", return_value=False),
        patch("chroot_distro.helpers.mount_targets.bind_mount_fd") as do_bind,
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", rootfs="/tmp/rootfs", holder=holder)

    do_bind.assert_called_once_with("/host/src", "/tmp/rootfs", ["mnt"], want="dir", recursive=False, options="")


def test_create_dev_nodes_via_holder(tmp_path):
    # The node is made by a stdlib call run inside the holder's namespaces,
    # addressed through the descriptor walk. mknod itself needs privileges,
    # so it is faked to create the plain file the walk then re-opens.
    holder = MagicMock()
    holder.call.side_effect = lambda fn: fn()
    (tmp_path / "dev").mkdir()

    def fake_mknod(name, mode, dev, *, dir_fd=None):
        os.close(os.open(name, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o644, dir_fd=dir_fd))

    with (
        patch("os.mknod", side_effect=fake_mknod) as mock_mknod,
        patch("chroot_distro.helpers.mount_targets.verify_dev_node", return_value=True),
    ):
        mm.create_dev_nodes(str(tmp_path), [("null", 1, 3, 0o666)], holder=holder)

    holder.call.assert_called_once()
    args = mock_mknod.call_args
    assert args.args[0] == "null"
    assert args.args[1] == 0o666 | stat.S_IFCHR
    assert args.args[2] == os.makedev(1, 3)


def test_create_dev_nodes_under_userns_binds_instead_of_mknod(tmp_path):
    # Inside a user namespace mknod is forbidden, so the host device node is
    # bind-mounted onto a stub created inside the holder.
    holder = MagicMock()
    holder.call.side_effect = lambda fn: fn()
    (tmp_path / "dev").mkdir()
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.helpers.mount_targets.bind_mount_fd") as mock_bind,
        patch("os.mknod") as mock_mknod,
    ):
        mm.create_dev_nodes(str(tmp_path), [("null", 1, 3, 0o666)], holder=holder, use_userns=True)

    # The stub is made and the host node bound over it, both inside the holder.
    holder.call.assert_called_once()
    mock_bind.assert_called_once_with("/dev/null", str(tmp_path), ["dev", "null"], want="any")
    mock_mknod.assert_not_called()
