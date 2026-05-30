import signal
from unittest.mock import MagicMock, call, patch

import pytest

from chroot_distro.commands.unmount import command_unmount
from chroot_distro.parser import ALIAS_TO_CANONICAL, build_parser


def test_parser_unmount():
    parser = build_parser()

    # Test basic parsing of 'unmount'
    args = parser.parse_args(["unmount", "alpine"])
    assert args.command == "unmount"
    assert args.container_name == "alpine"

    # Test basic parsing of 'umount' alias — argparse stores the actual
    # subcommand string used, not the canonical name.
    args = parser.parse_args(["umount", "debian"])
    assert args.command == "umount"
    assert args.container_name == "debian"

    # Test basic parsing of 'um' alias
    args = parser.parse_args(["um", "debian"])
    assert args.command == "um"
    assert args.container_name == "debian"

    # Test alias mapping
    assert ALIAS_TO_CANONICAL["umount"] == "unmount"
    assert ALIAS_TO_CANONICAL["um"] == "unmount"


@patch("chroot_distro.commands.unmount.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=False)
@patch("chroot_distro.commands.unmount.crit_error")
def test_unmount_container_not_installed(mock_crit_error, mock_isdir, mock_rootfs):
    args = MagicMock()
    args.container_name = "alpine"

    with pytest.raises(SystemExit) as exc_info:
        command_unmount(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with("container 'alpine' is not installed.")


@patch("chroot_distro.commands.unmount.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.unmount.ContainerLock")
@patch("chroot_distro.commands.unmount.session")
@patch("chroot_distro.commands.unmount.mount_manager")
@patch("chroot_distro.commands.unmount.log_info")
def test_unmount_no_active_sessions(mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs):
    args = MagicMock()
    args.container_name = "alpine"

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    command_unmount(args)

    mock_lock.assert_called_once_with("alpine", exclusive=True, command="unmount")
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs")
    mock_log.assert_any_call("Container 'alpine' successfully unmounted.")


@patch("chroot_distro.commands.unmount.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.unmount.ContainerLock")
@patch("chroot_distro.commands.unmount.session")
@patch("chroot_distro.commands.unmount.mount_manager")
@patch("chroot_distro.commands.unmount.log_info")
@patch("os.kill")
@patch("chroot_distro.commands.unmount.time")
def test_unmount_with_active_sessions_sigterm(mock_time, mock_kill, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs):
    """Processes exit after SIGTERM — no SIGKILL needed."""
    args = MagicMock()
    args.container_name = "alpine"

    # time.time() sequence:
    #   start_time = time.time()  -> 0
    #   while check              -> 0.1  (enters loop)
    mock_time.time.side_effect = [0, 0.1]
    mock_time.sleep = MagicMock()

    # get_active_chroot_pids sequence:
    #  1. Initial check (line 28)         -> [123, 456]  (triggers SIGTERM)
    #  2. Inside while loop (line 41)     -> []           (break)
    #  3. After while loop  (line 46)     -> []           (skip SIGKILL)
    mock_session.get_active_chroot_pids.side_effect = [[123, 456], [], []]
    mock_mount.get_active_mounts.return_value = []

    command_unmount(args)

    mock_kill.assert_has_calls([
        call(123, signal.SIGTERM),
        call(456, signal.SIGTERM),
    ])
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs")
    mock_log.assert_any_call("Container 'alpine' successfully unmounted.")


@patch("chroot_distro.commands.unmount.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.unmount.ContainerLock")
@patch("chroot_distro.commands.unmount.session")
@patch("chroot_distro.commands.unmount.mount_manager")
@patch("chroot_distro.commands.unmount.log_info")
@patch("os.kill")
@patch("chroot_distro.commands.unmount.time")
def test_unmount_with_active_sessions_sigkill(mock_time, mock_kill, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs):
    """Process survives SIGTERM; falls back to SIGKILL."""
    args = MagicMock()
    args.container_name = "alpine"

    # time.time() sequence:
    #   1. start_time (first loop)  -> 0
    #   2. while check              -> 0.1   (enters, still alive)
    #   3. while check              -> 3.0   (> 2 s, exits loop)
    #   4. start_time (second loop) -> 4.0
    #   5. while check              -> 4.1   (enters, now gone)
    mock_time.time.side_effect = [0, 0.1, 3.0, 4.0, 4.1]
    mock_time.sleep = MagicMock()

    # get_active_chroot_pids sequence:
    #  1. Initial check              -> [123]   (triggers SIGTERM)
    #  2. While-loop iter 1          -> [123]   (still alive, sleep)
    #  3. After first while-loop     -> [123]   (still alive → SIGKILL)
    #  4. While-loop iter 1 (kill)   -> []      (break)
    #  5. After second while-loop    -> []      (done)
    mock_session.get_active_chroot_pids.side_effect = [
        [123], [123], [123], [], [],
    ]
    mock_mount.get_active_mounts.return_value = []

    command_unmount(args)

    mock_kill.assert_has_calls([
        call(123, signal.SIGTERM),
        call(123, signal.SIGKILL),
    ])
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs")
    mock_log.assert_any_call("Container 'alpine' successfully unmounted.")
