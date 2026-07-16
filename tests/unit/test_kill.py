import signal
from unittest.mock import MagicMock, call, patch

import pytest

from chroot_distro.commands.kill import command_kill
from chroot_distro.parser import build_parser


def test_parser_kill():
    parser = build_parser()
    args = parser.parse_args(["kill", "ubuntu"])
    assert args.command == "kill"
    assert args.container_or_pid == "ubuntu"


@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=False)
@patch("chroot_distro.commands.kill.crit_error")
def test_kill_container_not_installed(mock_crit_error, mock_isdir, mock_rootfs):
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    with pytest.raises(SystemExit) as exc_info:
        command_kill(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with("container 'ubuntu' is not installed.")


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
def test_kill_not_running(mock_log, mock_mount, mock_session, mock_isdir, mock_rootfs, *_mocks):
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    command_kill(args)

    mock_log.assert_called_once_with("Container 'ubuntu' is not running.")


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch("chroot_distro.syscalls.umount.native_umount")
def test_kill_standard_unmount_success(
    mock_native_umount, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """If standard unmount succeeds, we don't need lazy/kill/forceful."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.return_value = []
    # get_active_mounts returns active mounts for first check, then empty for subsequent checks
    mock_mount.get_active_mounts.side_effect = [
        ["/mock/containers/ubuntu/rootfs/proc"],  # initial check
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 1 check
        [],  # Step 2 check
        [],  # Step 3 check
        [],  # Step 4 check
    ]

    mock_lock_instance = MagicMock()
    mock_lock_instance.acquire.return_value = True
    mock_lock.return_value = mock_lock_instance

    mock_native_umount.return_value = None

    command_kill(args)

    mock_lock_instance.acquire.assert_called_once()
    mock_native_umount.assert_called_once_with("/mock/containers/ubuntu/rootfs/proc", lazy=False, force=False)
    mock_session.reset.assert_called_once_with("ubuntu")
    mock_log.assert_any_call("Container 'ubuntu' successfully killed and unmounted.")
    mock_lock_instance.release.assert_called_once()


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch("chroot_distro.syscalls.umount.native_umount")
def test_kill_lazy_unmount_success(
    mock_native_umount, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """If standard unmount fails, lazy unmount succeeds."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.return_value = []
    # get_active_mounts sequences:
    mock_mount.get_active_mounts.side_effect = [
        ["/mock/containers/ubuntu/rootfs/proc"],  # initial check
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 1 check
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 2 check
        [],  # Step 3 check
        [],  # Step 4 check
    ]

    mock_lock_instance = MagicMock()
    mock_lock_instance.acquire.return_value = True
    mock_lock.return_value = mock_lock_instance

    # Standard umount fails (raises OSError), lazy umount succeeds (returns None)
    mock_native_umount.side_effect = [OSError("mock fail"), None]

    command_kill(args)

    mock_native_umount.assert_has_calls(
        [
            call("/mock/containers/ubuntu/rootfs/proc", lazy=False, force=False),
            call("/mock/containers/ubuntu/rootfs/proc", lazy=True, force=False),
        ]
    )
    mock_session.reset.assert_called_once_with("ubuntu")
    mock_log.assert_any_call("Container 'ubuntu' successfully killed and unmounted.")


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch("chroot_distro.syscalls.umount.native_umount")
@patch("chroot_distro.commands.kill.os.kill")
@patch("chroot_distro.commands.kill.time.sleep")
@patch("chroot_distro.commands.kill.time.time")
def test_kill_process_then_unmount(
    mock_time,
    mock_sleep,
    mock_kill,
    mock_native_umount,
    mock_log,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_rootfs,
    *_mocks,
):
    """Processes are active, we terminate them and successfully retry unmounting."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    # PIDs sequence:
    # 1. Initial check (PIDs active) -> [1000]
    # 2. Step 3 check                -> [1000]
    # 3. _wait_until_gone loop check -> [] (exited after SIGTERM)
    mock_session.get_active_chroot_pids.side_effect = [[1000], [1000], []]

    # Mounts sequence:
    # 1. Initial check                               -> ["/mock/containers/ubuntu/rootfs/proc"]
    # 2. Step 1 (standard)                           -> ["/mock/containers/ubuntu/rootfs/proc"]
    # 3. Step 2 (lazy)                               -> ["/mock/containers/ubuntu/rootfs/proc"]
    # 4. Step 3 (post-kill standard retry)           -> ["/mock/containers/ubuntu/rootfs/proc"]
    # 5. Step 3 (post-kill lazy retry)               -> []
    # 6. Step 4 (forceful check)                     -> []
    mock_mount.get_active_mounts.side_effect = [
        ["/mock/containers/ubuntu/rootfs/proc"],
        ["/mock/containers/ubuntu/rootfs/proc"],
        ["/mock/containers/ubuntu/rootfs/proc"],
        ["/mock/containers/ubuntu/rootfs/proc"],
        ["/mock/containers/ubuntu/rootfs/proc"],
        [],
        [],
    ]

    mock_lock_instance = MagicMock()
    mock_lock_instance.acquire.return_value = True
    mock_lock.return_value = mock_lock_instance

    mock_time.side_effect = [0, 0.1, 0.2, 0.3]

    # Standard umounts fail, lazy umounts succeed
    mock_native_umount.side_effect = [
        OSError("mock fail"),  # Step 1 standard
        OSError("mock fail"),  # Step 2 lazy
        OSError("mock fail"),  # Step 3 post-kill standard
        None,  # Step 3 post-kill lazy
    ]

    command_kill(args)

    mock_kill.assert_called_once_with(1000, signal.SIGTERM)
    mock_session.reset.assert_called_once_with("ubuntu")
    mock_log.assert_any_call("Container 'ubuntu' successfully killed and unmounted.")


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch("chroot_distro.syscalls.umount.native_umount")
@patch("chroot_distro.commands.kill.crit_error")
def test_kill_forceful_failure_diagnostic(
    mock_crit_error, mock_native_umount, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """If forceful unmount also fails, we output detailed diagnostics."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.return_value = []
    # get_active_mounts always returns a mount
    mock_mount.get_active_mounts.return_value = ["/mock/containers/ubuntu/rootfs/proc"]

    mock_lock_instance = MagicMock()
    mock_lock_instance.acquire.return_value = True
    mock_lock.return_value = mock_lock_instance

    # All umount commands fail
    mock_native_umount.side_effect = OSError("mock fail")

    with pytest.raises(SystemExit) as exc_info:
        command_kill(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with(
        "Failed to kill and unmount container 'ubuntu'.\n"
        "Remaining active mounts:\n"
        "  - /mock/containers/ubuntu/rootfs/proc\n"
        "Remaining active process PIDs: None"
    )


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch("chroot_distro.syscalls.umount.native_umount")
@patch("chroot_distro.commands.kill.os.kill")
@patch("chroot_distro.commands.kill.time.sleep")
@patch("chroot_distro.commands.kill.time.time")
def test_kill_lock_conflict_bypass(
    mock_time,
    mock_sleep,
    mock_kill,
    mock_native_umount,
    mock_log,
    mock_mount,
    mock_session,
    mock_lock,
    mock_isdir,
    mock_rootfs,
    *_mocks,
):
    """When container lock is busy initially, we bypass it, kill processes, and acquire it afterward."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.side_effect = [[1000], [1000], []]
    mock_mount.get_active_mounts.side_effect = [
        ["/mock/containers/ubuntu/rootfs/proc"],  # initial check
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 1 standard
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 2 lazy
        ["/mock/containers/ubuntu/rootfs/proc"],  # Step 3 post-kill standard
        [],  # Step 3 post-kill lazy
        [],  # Step 4 check
    ]

    mock_lock_instance = MagicMock()
    # First acquire fails, second acquire (after processes killed) succeeds
    mock_lock_instance.acquire.side_effect = [False, True]
    mock_lock.return_value = mock_lock_instance

    mock_time.side_effect = [0, 0.1, 0.2, 0.3]
    mock_native_umount.return_value = None

    command_kill(args)

    # We logged a warning/info about lock conflict
    mock_log.assert_any_call("Container 'ubuntu' is busy (active sessions exist). Forcing cleanup...")
    # Two calls to acquire
    assert mock_lock_instance.acquire.call_count == 2
    # Lock released at the end
    mock_lock_instance.release.assert_called_once()


# ---------- PID-based kill tests ----------


def test_parser_kill_with_pid():
    parser = build_parser()
    args = parser.parse_args(["kill", "111579"])
    assert args.command == "kill"
    assert args.container_or_pid == "111579"


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.namespace.release_holder")
@patch("chroot_distro.commands.kill.namespace.clear_isolation_mode")
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/httpd/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.ContainerLock")
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
@patch(
    "chroot_distro.helpers.session_registry.active_sessions",
    return_value=[{"pid": 111579, "container": "httpd"}],
)
def test_kill_by_pid_resolves_container(
    mock_active, mock_log, mock_mount, mock_session, mock_lock, mock_isdir, mock_rootfs, *_mocks
):
    """Numeric PID that exists in the session registry kills the owning container."""
    args = MagicMock()
    args.container_or_pid = "111579"

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    mock_lock_instance = MagicMock()
    mock_lock_instance.acquire.return_value = True
    mock_lock.return_value = mock_lock_instance

    command_kill(args)

    mock_log.assert_any_call("Container 'httpd' is not running.")


@patch(
    "chroot_distro.helpers.session_registry.active_sessions",
    return_value=[],
)
@patch("chroot_distro.commands.kill.crit_error")
def test_kill_by_pid_not_found(mock_crit_error, mock_active):
    """Numeric PID not in the session registry prints error and exits."""
    args = MagicMock()
    args.container_or_pid = "99999"

    with pytest.raises(SystemExit) as exc_info:
        command_kill(args)

    assert exc_info.value.code == 1
    mock_crit_error.assert_called_once_with("No running container found with PID 99999.")


@patch("chroot_distro.commands.kill.namespace.get_live_holder", return_value=None)
@patch("chroot_distro.commands.kill.container_rootfs", return_value="/mock/containers/ubuntu/rootfs")
@patch("os.path.isdir", return_value=True)
@patch("chroot_distro.commands.kill.session")
@patch("chroot_distro.commands.kill.mount_manager")
@patch("chroot_distro.commands.kill.log_info")
def test_kill_by_name_still_works(mock_log, mock_mount, mock_session, mock_isdir, mock_rootfs, *_mocks):
    """Name-based kill still works with the renamed arg."""
    args = MagicMock()
    args.container_or_pid = "ubuntu"

    mock_session.get_active_chroot_pids.return_value = []
    mock_mount.get_active_mounts.return_value = []

    command_kill(args)

    mock_log.assert_called_once_with("Container 'ubuntu' is not running.")
