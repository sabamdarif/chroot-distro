"""Tests for namespace-aware mount_manager helpers."""

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


@patch("chroot_distro.helpers.mount_manager._run_mount_cmd")
def test_safe_mount_via_holder(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    holder = MagicMock()
    holder.is_mounted = MagicMock(return_value=False)

    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
        patch("shutil.which", return_value="/bin/mount"),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder)

    mock_run.assert_called_once()
    assert mock_run.call_args[0][0][0].endswith("mount")
    assert mock_run.call_args[0][0][1:] == ["--bind", "/host/src", "/tmp/rootfs/mnt"]
    assert mock_run.call_args[0][1] is holder


def test_create_dev_nodes_via_holder():
    holder = MagicMock()
    holder.run.return_value = MagicMock(returncode=0)
    rootfs = "/tmp/rootfs"
    nodes = [("null", 1, 3, 0o666)]
    mm.create_dev_nodes(rootfs, nodes, holder=holder)
    holder.run.assert_called_once_with(
        ["mknod", "-m", "666", "/tmp/rootfs/dev/null", "c", "1", "3"],
        capture_output=True,
        text=True,
    )

