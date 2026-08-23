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
    holder = MagicMock()
    holder.is_mounted = MagicMock(return_value=False)

    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder)

    holder.do_bind_mount.assert_called_once_with(
        "/host/src", "/tmp/rootfs/mnt", recursive=False, options=""
    )


def test_create_dev_nodes_via_holder():
    # The node is made by a stdlib call run inside the holder's namespaces.
    holder = MagicMock()
    holder.call.side_effect = lambda fn: fn() or b""
    rootfs = "/tmp/rootfs"
    nodes = [("null", 1, 3, 0o666)]
    with (
        patch("os.path.exists", return_value=False),
        patch("os.mknod") as mock_mknod,
        patch("os.chmod") as mock_chmod,
    ):
        mm.create_dev_nodes(rootfs, nodes, holder=holder)

    holder.call.assert_called_once()
    mock_mknod.assert_called_once_with("/tmp/rootfs/dev/null", 0o666 | stat.S_IFCHR, os.makedev(1, 3))
    mock_chmod.assert_called_once_with("/tmp/rootfs/dev/null", 0o666)


def test_create_dev_nodes_under_userns_binds_instead_of_mknod():
    # Inside a user namespace mknod is forbidden, so the host device node is
    # bind-mounted onto a stub created inside the holder.
    holder = MagicMock()
    holder.call.return_value = b""
    rootfs = "/tmp/rootfs"
    nodes = [("null", 1, 3, 0o666)]
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.helpers.mount_manager.safe_mount") as mock_safe,
        patch("os.mknod") as mock_mknod,
    ):
        mm.create_dev_nodes(rootfs, nodes, holder=holder, use_userns=True)

    # The stub is created inside the holder, then the host node is bound over it.
    holder.call.assert_called_once()
    mock_safe.assert_called_once_with("/dev/null", "/tmp/rootfs/dev/null", holder=holder)
    mock_mknod.assert_not_called()
