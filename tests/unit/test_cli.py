from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.cli import _ensure_root_user, main
from chroot_distro.exceptions import RootRequiredError


def test_ensure_root_user():
    # As non-root with no_elevate=True, it should raise RootRequiredError
    with patch("os.getuid", return_value=1000), pytest.raises(RootRequiredError):
        _ensure_root_user(no_elevate=True)

    # As non-root with no_elevate=False, it should call elevate_or_die
    with patch("os.getuid", return_value=1000), \
         patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
        _ensure_root_user(no_elevate=False)
        mock_elevate.assert_called_once()

    # As root, it should pass without raising and not call elevate_or_die
    with patch("os.getuid", return_value=0), \
         patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
        _ensure_root_user()
        mock_elevate.assert_not_called()


def test_main_help():
    # Running with no args or --help should trigger command_help and exit 0
    with patch("sys.argv", ["chroot-distro"]), \
         patch("chroot_distro.cli.command_help") as mock_help:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_help.assert_called_once()

    with patch("sys.argv", ["chroot-distro", "--help"]), \
         patch("chroot_distro.cli.command_help") as mock_help:

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_help.assert_called_once()


def test_main_unknown_command():
    # Running with unknown command should exit 1
    with patch("sys.argv", ["chroot-distro", "unknowncommand"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_main_list():
    # Running list should call command_list
    mock_list = MagicMock()
    with patch("sys.argv", ["chroot-distro", "list"]), \
         patch("os.getuid", return_value=0), \
         patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}):
        main()
        mock_list.assert_called_once()



def test_main_login_requires_root():
    # Running login as non-root (UID 1000) should attempt privilege elevation
    # Mock elevate_or_die to raise RootRequiredError to simulate failed/disabled elevation
    with patch("sys.argv", ["chroot-distro", "login", "alpine"]), \
         patch("os.getuid", return_value=1000), \
         patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_main_no_elevate_flag():
    # When --no-elevate is passed, it should exit with 1 immediately without calling elevate_or_die
    with patch("sys.argv", ["chroot-distro", "--no-elevate", "login", "alpine"]), \
         patch("os.getuid", return_value=1000), \
         patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_elevate.assert_not_called()


@patch("chroot_distro.cli.IS_TERMUX", True)
def test_main_termux_list_does_not_require_root():
    # In Termux, 'list' does not require root
    mock_list = MagicMock()
    with patch("sys.argv", ["chroot-distro", "list"]), \
         patch("os.getuid", return_value=1000), \
         patch("chroot_distro.elevate.elevate_or_die") as mock_elevate, \
         patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}):
        main()
        mock_list.assert_called_once()
        mock_elevate.assert_not_called()


@patch("chroot_distro.cli.IS_TERMUX", False)
def test_main_linux_list_requires_root():
    # In normal Linux, 'list' requires root
    mock_list = MagicMock()
    with patch("sys.argv", ["chroot-distro", "list"]), \
         patch("os.getuid", return_value=1000), \
         patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")) as mock_elevate, \
         patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_elevate.assert_called_once()
        mock_list.assert_not_called()


