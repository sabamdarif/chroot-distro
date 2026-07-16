import signal
from unittest.mock import MagicMock, call, patch, ANY

import pytest

from chroot_distro.commands.remove import command_remove
from chroot_distro.parser import build_parser


def test_parser_remove():
    parser = build_parser()

    # Test basic parsing of 'remove'
    args = parser.parse_args(["remove", "alpine"])
    assert args.command == "remove"
    assert args.container_name == ["alpine"]

    # Test basic parsing of 'rm' alias
    args = parser.parse_args(["rm", "debian"])
    assert args.command == "rm"
    assert args.container_name == ["debian"]

    # Multiple containers at once
    args = parser.parse_args(["remove", "alpine", "debian", "ubuntu"])
    assert args.container_name == ["alpine", "debian", "ubuntu"]


@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=False)
@patch("chroot_distro.commands.remove.crit_error")
def test_remove_container_not_installed(mock_crit_error, mock_isdir, mock_rootfs):
    args = MagicMock()
    args.container_name = "alpine"

    with pytest.raises(SystemExit) as exc_info:
        command_remove(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with("container 'alpine' is not installed.")


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("chroot_distro.commands.remove.container_dir", return_value="/mock/containers/alpine")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove._remove_path", return_value=True)
@patch("chroot_distro.commands.remove.log_info")
@patch("os.unlink")
def test_remove_no_active_sessions_or_mounts(
    mock_unlink,
    mock_log,
    mock_remove_path,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_dir,
    mock_rootfs,
    *_mocks,
):
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    command_remove(args)

    mock_lock.assert_called_once_with("alpine", exclusive=True, command="remove")
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs", holder=None)
    # _remove_path is called for the container dir, then for the data dir
    mock_remove_path.assert_any_call("/mock/containers/alpine", ANY)
    assert mock_remove_path.call_count == 2
    mock_log.assert_any_call("Finished removing the container.")


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("chroot_distro.commands.remove.container_dir", return_value="/mock/containers/alpine")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove._remove_path", return_value=True)
@patch("chroot_distro.commands.remove.log_info")
@patch("os.kill")
@patch("os.unlink")
@patch("chroot_distro.commands.remove.time")
def test_remove_with_active_sessions_sigterm(
    mock_time,
    mock_unlink,
    mock_kill,
    mock_log,
    mock_remove_path,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_dir,
    mock_rootfs,
    *_mocks,
):
    """Processes exit after SIGTERM — no SIGKILL needed."""
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    # time.time() sequence for SIGTERM loop
    mock_time.time.side_effect = [0, 0.1]
    mock_time.sleep = MagicMock()

    # get_active_chroot_pids sequence:
    # 1. Initial check (active_pids) -> [123, 456]
    # 2. Inside while loop -> [] (break)
    # 3. After while loop -> []
    # 4. Busy check check PIDs -> []
    mock_session.get_active_chroot_pids.side_effect = [[123, 456], [], [], []]
    mock_mount.get_active_mounts.return_value = []

    command_remove(args)

    mock_kill.assert_has_calls(
        [
            call(123, signal.SIGTERM),
            call(456, signal.SIGTERM),
        ]
    )
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs", holder=None)
    # _remove_path is called for the container dir, then for the data dir
    mock_remove_path.assert_any_call("/mock/containers/alpine", ANY)
    assert mock_remove_path.call_count == 2
    mock_log.assert_any_call("Finished removing the container.")


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("chroot_distro.commands.remove.container_dir", return_value="/mock/containers/alpine")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove._remove_path", return_value=True)
@patch("chroot_distro.commands.remove.log_info")
@patch("os.kill")
@patch("os.unlink")
@patch("chroot_distro.commands.remove.time")
def test_remove_with_active_sessions_sigkill(
    mock_time,
    mock_unlink,
    mock_kill,
    mock_log,
    mock_remove_path,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_dir,
    mock_rootfs,
    *_mocks,
):
    """Processes exit after SIGKILL."""
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    # time.time() sequence for SIGTERM & SIGKILL loops
    mock_time.time.side_effect = [0, 0.1, 3.0, 4.0, 4.1]
    mock_time.sleep = MagicMock()

    # get_active_chroot_pids sequence:
    # 1. Initial check (active_pids) -> [123]
    # 2. While-loop iter 1 -> [123] (still alive)
    # 3. After first while-loop -> [123] (still alive -> SIGKILL)
    # 4. While-loop iter 1 (kill) -> [] (break)
    # 5. After second while-loop -> []
    # 6. Busy check check PIDs -> []
    mock_session.get_active_chroot_pids.side_effect = [[123], [123], [123], [], [], []]
    mock_mount.get_active_mounts.return_value = []

    command_remove(args)

    mock_kill.assert_has_calls(
        [
            call(123, signal.SIGTERM),
            call(123, signal.SIGKILL),
        ]
    )
    mock_session.reset.assert_called_once_with("alpine")
    mock_mount.unmount_all.assert_called_once_with("/mock/containers/alpine/rootfs", holder=None)
    # _remove_path is called for the container dir, then for the data dir
    mock_remove_path.assert_any_call("/mock/containers/alpine", ANY)
    assert mock_remove_path.call_count == 2
    mock_log.assert_any_call("Finished removing the container.")


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove.crit_error")
@patch("os.kill")
@patch("chroot_distro.commands.remove.time")
def test_remove_still_busy_processes(
    mock_time, mock_kill, mock_crit_error, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """Processes fail to exit even after SIGKILL -> Abort remove."""
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    # time.time() sequence for SIGTERM & SIGKILL loops
    mock_time.time.side_effect = [0, 0.1, 3.0, 4.0, 4.1, 6.0]
    mock_time.sleep = MagicMock()

    # get_active_chroot_pids sequence:
    # 1. Initial check (active_pids) -> [123]
    # 2. While-loop iter 1 -> [123] (still alive)
    # 3. After first while-loop -> [123]
    # 4. While-loop iter 1 (kill) -> [123]
    # 5. After second while-loop -> [123]
    # 6. Busy check check PIDs -> [123] (still active)
    mock_session.get_active_chroot_pids.side_effect = [[123], [123], [123], [123], [123], [123]]
    mock_mount.get_active_mounts.return_value = []

    with pytest.raises(SystemExit) as exc_info:
        command_remove(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with(
        "Cannot remove container 'alpine': the distro is busy. Kill any running processes and try again."
    )


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove.crit_error")
def test_remove_still_busy_mounts(
    mock_crit_error, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """Mounts remain active even after unmount_all -> Abort remove."""
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = ["/mock/containers/alpine/rootfs/proc"]

    with pytest.raises(SystemExit) as exc_info:
        command_remove(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with(
        "Cannot remove container 'alpine': the distro is busy. Kill any running processes and try again."
    )


def test_count_files(tmp_path):
    from chroot_distro.commands.remove import _count_files

    # Empty directory
    assert _count_files(str(tmp_path)) == 1

    # Directory with files
    (tmp_path / "file1.txt").write_text("hello")
    (tmp_path / "file2.txt").write_text("world")
    assert _count_files(str(tmp_path)) == 3

    # Nested directories
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("nested")
    assert _count_files(str(tmp_path)) == 5  # tmp_path, file1, file2, subdir, nested.txt


@patch("chroot_distro.commands.remove.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.remove.container_rootfs", return_value="/mock/containers/alpine/rootfs")
@patch("chroot_distro.commands.remove.container_dir", return_value="/mock/containers/alpine")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.remove.ContainerLock")
@patch("chroot_distro.commands.remove.session")
@patch("chroot_distro.commands.remove.mount_manager")
@patch("chroot_distro.commands.remove._remove_path", return_value=True)
@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.draw_count_bar")
@patch("chroot_distro.progress.clear_bar")
@patch("chroot_distro.commands.remove._count_files", return_value=10)
@patch("os.unlink")
def test_remove_progress_bar(
    mock_unlink,
    mock_count_files,
    mock_clear_bar,
    mock_draw_bar,
    mock_active,
    mock_remove_path,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_dir,
    mock_rootfs,
    *_mocks,
):
    args = MagicMock()
    args.container_name = "alpine"
    args.verbose = False

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    # Mock _remove_path to trigger the callback
    def fake_remove_path(path, on_remove):
        if on_remove:
            on_remove("/mock/containers/alpine/somefile")
        return True
    mock_remove_path.side_effect = fake_remove_path

    command_remove(args)

    # progress_active should have been checked, and draw_count_bar called
    mock_active.assert_called()
    mock_draw_bar.assert_has_calls([
        call(1, 20, label="Removing", unit="files"),
        call(2, 20, label="Removing", unit="files"),
    ])
    mock_clear_bar.assert_called_once()

