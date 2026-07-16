from unittest.mock import patch

from chroot_distro.syscalls.mount import (
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_RDONLY,
    _parse_and_split_mount_options,
    mount_filesystem,
)


def test_parse_and_split_mount_options():
    # Empty options
    flags, data = _parse_and_split_mount_options("")
    assert flags == 0
    assert data == ""

    # Only generic options
    flags, data = _parse_and_split_mount_options("nosuid,nodev,noexec")
    assert flags == MS_NOSUID | MS_NODEV | MS_NOEXEC
    assert data == ""

    # Mix of generic and filesystem-specific options
    flags, data = _parse_and_split_mount_options("hidepid=2,nosuid,nodev,noexec")
    assert flags == MS_NOSUID | MS_NODEV | MS_NOEXEC
    assert data == "hidepid=2"

    # Only filesystem-specific options
    flags, data = _parse_and_split_mount_options("mode=0755,size=64m")
    assert flags == 0
    assert data == "mode=0755,size=64m"

    # Initial flags are preserved and merged
    flags, data = _parse_and_split_mount_options("ro,nosuid", initial_flags=MS_NODEV)
    assert flags == MS_RDONLY | MS_NOSUID | MS_NODEV
    assert data == ""

@patch("chroot_distro.syscalls.mount.native_mount")
def test_mount_filesystem_splits_options(mock_native_mount):
    mount_filesystem("proc", "/chroot/proc", "proc", options="hidepid=2,nosuid,nodev,noexec")
    mock_native_mount.assert_called_once_with(
        "proc",
        "/chroot/proc",
        "proc",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        "hidepid=2"
    )
