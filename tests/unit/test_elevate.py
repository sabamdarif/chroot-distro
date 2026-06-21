import os
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.elevate import (
    _find_escalation_tool,
    elevate_or_die,
    get_reexec_argv,
    is_root,
)
from chroot_distro.exceptions import RootRequiredError


def test_is_root():
    with patch("os.getuid", return_value=0):
        assert is_root() is True

    with patch("os.getuid", return_value=1000):
        assert is_root() is False


def test_get_reexec_argv_absolute():
    # If sys.argv[0] is absolute and not .py, return as is
    with patch("sys.argv", ["/usr/bin/chroot-distro", "login", "alpine"]):
        argv = get_reexec_argv()
        assert argv == ["/usr/bin/chroot-distro", "login", "alpine"]


def test_get_reexec_argv_relative_resolved():
    # If sys.argv[0] is relative but in path, resolve it
    with (
        patch("sys.argv", ["chroot-distro", "login", "alpine"]),
        patch("shutil.which", return_value="/usr/local/bin/chroot-distro"),
    ):
        argv = get_reexec_argv()
        assert argv == ["/usr/local/bin/chroot-distro", "login", "alpine"]


def test_get_reexec_argv_python_script():
    # If sys.argv[0] ends with .py, prepend sys.executable
    with patch("sys.argv", ["/path/to/main.py", "list"]), patch("sys.executable", "/usr/bin/python3"):
        argv = get_reexec_argv()
        assert argv == ["/usr/bin/python3", "/path/to/main.py", "list"]


@patch("chroot_distro.elevate.IS_TERMUX", True)
def test_find_escalation_tool_termux():
    # Termux: sudo -> doas -> pkexec -> su
    # 1. sudo available
    with patch(
        "shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("sudo", "doas", "pkexec", "su") else None
    ):
        assert _find_escalation_tool() == ["sudo"]

    # 2. doas available (no sudo)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("doas", "pkexec", "su") else None):
        assert _find_escalation_tool() == ["doas", "--"]

    # 3. pkexec available (no sudo, no doas)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("pkexec", "su") else None):
        assert _find_escalation_tool() == ["pkexec", "--disable-internal-agent"]

    # 4. su available (no sudo, doas, pkexec)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd == "su" else None):
        assert _find_escalation_tool() == ["su", "-c"]

    # 5. none available
    with patch("shutil.which", return_value=None):
        assert _find_escalation_tool() is None


@patch("chroot_distro.elevate.IS_TERMUX", False)
def test_find_escalation_tool_linux():
    # Linux: sudo -> doas -> pkexec -> su
    # 1. sudo available
    with patch(
        "shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("sudo", "doas", "pkexec", "su") else None
    ):
        assert _find_escalation_tool() == ["sudo", "-E"]

    # 2. doas available (no sudo)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("doas", "pkexec", "su") else None):
        assert _find_escalation_tool() == ["doas", "--"]

    # 3. pkexec available (no sudo, no doas)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("pkexec", "su") else None):
        assert _find_escalation_tool() == ["pkexec", "--disable-internal-agent"]

    # 4. su available (no sudo, doas, pkexec)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd == "su" else None):
        assert _find_escalation_tool() == ["su", "-c"]

    # 5. none available
    with patch("shutil.which", return_value=None):
        assert _find_escalation_tool() is None


def test_elevate_or_die_already_root():
    with patch("chroot_distro.elevate.is_root", return_value=True), patch("os.execvp") as mock_exec:
        elevate_or_die()
        mock_exec.assert_not_called()


def test_elevate_or_die_loop_detected():
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch.dict("os.environ", {"_CHROOT_DISTRO_ELEVATING": "1"}),
        pytest.raises(RootRequiredError, match="Privilege elevation loop detected"),
    ):
        elevate_or_die()


def test_elevate_or_die_no_tool():
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=None),
        pytest.raises(RootRequiredError, match="requires root privileges, but no privilege elevation tool"),
    ):
        elevate_or_die()


def test_elevate_or_die_exec_sudo():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["sudo", "-E"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "alpine"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {}),
    ):
        elevate_or_die()

        mock_exec.assert_called_once()
        args, _kwargs = mock_exec.call_args
        assert args[0] == "sudo"
        assert args[1] == ["sudo", "-E", "/usr/bin/chroot-distro", "login", "alpine"]
        assert os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1"


def test_elevate_or_die_exec_su():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["su", "-c"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "alpine"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {}),
    ):
        elevate_or_die()

        mock_exec.assert_called_once()
        args, _kwargs = mock_exec.call_args
        assert args[0] == "su"
        assert args[1] == ["su", "-c", "/usr/bin/chroot-distro login alpine"]
        assert os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1"
