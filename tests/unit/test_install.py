from unittest.mock import patch

from chroot_distro.commands.install import _run_install


@patch("chroot_distro.commands.install.pull_image")
@patch("chroot_distro.commands.install._write_incomplete_marker")
@patch("chroot_distro.commands.install.os.makedirs")
@patch("chroot_distro.commands.install.os.path.isdir", return_value=False)
@patch("chroot_distro.commands.install.ContainerLock")
@patch("chroot_distro.commands.install.log_info")
def test_run_install_workers_log(mock_log, mock_lock, mock_isdir, mock_makedirs, mock_marker, mock_pull_image):
    # Case 1: Workers is default (4), should not print workers info
    with patch("chroot_distro.commands.install.layer_download_workers", return_value=4):
        _run_install("my-container", "alpine", None, None, "x86_64")

        # Verify it printed the standard installing message
        mock_log.assert_any_call("Installing 'alpine:latest' as 'my-container'...")
        # Verify it did not print "Parallel download workers: ..."
        for call_args in mock_log.call_args_list:
            assert "Parallel download workers" not in call_args[0][0]

    # Case 2: Workers is non-default (6), should print workers info
    mock_log.reset_mock()
    with patch("chroot_distro.commands.install.layer_download_workers", return_value=6):
        _run_install("my-container", "alpine", None, None, "x86_64")

        # Verify it printed the standard installing message
        mock_log.assert_any_call("Installing 'alpine:latest' as 'my-container'...")
        # Verify it printed "Parallel download workers: 6"
        mock_log.assert_any_call("Parallel download workers: 6")
