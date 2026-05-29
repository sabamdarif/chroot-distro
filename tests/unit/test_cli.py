from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.cli import _ensure_root_user, main
from chroot_distro.exceptions import RootRequiredError


def test_ensure_root_user():
    # As non-root, it should raise RootRequiredError
    with patch("os.getuid", return_value=1000), pytest.raises(RootRequiredError):
        _ensure_root_user()

    # As root, it should pass without raising
    with patch("os.getuid", return_value=0):
        _ensure_root_user()


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
         patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}):
        main()
        mock_list.assert_called_once()



def test_main_login_requires_root():
    # Running login as non-root (UID 1000) should raise SystemExit(1)
    with patch("sys.argv", ["chroot-distro", "login", "alpine"]), \
         patch("os.getuid", return_value=1000):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

