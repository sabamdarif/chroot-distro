import os
from unittest.mock import MagicMock, patch
import pytest

from chroot_distro.commands.login.env import resolve_term
from chroot_distro.commands.login.chroot_cmd import build_chroot_args


def test_resolve_term_empty():
    assert resolve_term("/fake/rootfs", "") == "xterm-256color"
    assert resolve_term("/fake/rootfs", None) == "xterm-256color"


def test_resolve_term_invalid_char():
    assert resolve_term("/fake/rootfs", "-xterm") == "xterm-256color"


def test_resolve_term_exists(tmp_path):
    # Setup dummy terminfo folder inside tmp_path
    terminfo_dir = tmp_path / "usr" / "share" / "terminfo" / "x"
    terminfo_dir.mkdir(parents=True)
    ghostty_file = terminfo_dir / "xterm-ghostty"
    ghostty_file.touch()

    # Should resolve successfully
    res = resolve_term(str(tmp_path), "xterm-ghostty")
    assert res == "xterm-ghostty"


def test_resolve_term_not_exists(tmp_path):
    res = resolve_term(str(tmp_path), "nonexistent-terminal-type")
    assert res == "xterm-256color"


def test_resolve_term_exists_termux(tmp_path):
    from chroot_distro.commands.login.env import TERMUX_PREFIX
    termux_usr = TERMUX_PREFIX.lstrip("/")

    # Setup dummy terminfo folder inside tmp_path under Termux path
    terminfo_dir = tmp_path / termux_usr / "share" / "terminfo" / "x"
    terminfo_dir.mkdir(parents=True)
    ghostty_file = terminfo_dir / "xterm-ghostty"
    ghostty_file.touch()

    # Should resolve successfully
    res = resolve_term(str(tmp_path), "xterm-ghostty")
    assert res == "xterm-ghostty"


def test_build_chroot_args_fault_tolerant_cd():
    # Test that when a workdir is specified, it wraps the command with a fault-tolerant cd.
    args = build_chroot_args(
        rootfs="/fake/rootfs",
        login_uid="1000",
        login_gid="1000",
        groups=["1000", "4"],
        workdir="/home/saba",
        inner_cmd=["/bin/bash", "-l"]
    )

    assert "chroot" in args
    assert "--userspec=1000:1000" in args
    assert "--groups=1000,4" in args
    assert "/fake/rootfs" in args
    
    # Verify the wrapped cd command structure
    assert "/bin/sh" in args
    assert "-c" in args
    wrapped_cmd = args[-1]
    assert "cd /home/saba 2>/dev/null || cd /" in wrapped_cmd
    assert "exec /bin/bash -l" in wrapped_cmd


def test_build_chroot_args_no_workdir():
    args = build_chroot_args(
        rootfs="/fake/rootfs",
        login_uid="1000",
        login_gid="1000",
        groups=["1000", "4"],
        workdir="",
        inner_cmd=["/bin/bash", "-l"]
    )
    # When no workdir is specified, it should NOT wrap it with cd.
    assert "/bin/sh" not in args
    assert args[-2:] == ["/bin/bash", "-l"]


@patch("chroot_distro.commands.login.resolve_rootfs_path")
@patch("os.path.exists")
@patch("os.stat")
@patch("os.chown")
@patch("os.chmod")
def test_fix_sudo_permissions(mock_chmod, mock_chown, mock_stat, mock_exists, mock_resolve):
    from chroot_distro.commands.login import _fix_sudo_permissions

    # Mock resolution and existence of files
    mock_resolve.side_effect = lambda rf, gp: rf + gp
    mock_exists.return_value = True

    # Setup stat return values: say UID/GID are 1000 (needs change) and mode is incorrect
    mock_stat_obj = MagicMock()
    mock_stat_obj.st_uid = 1000
    mock_stat_obj.st_gid = 1000
    mock_stat_obj.st_mode = 0o100644  # regular file, mode 644
    mock_stat.return_value = mock_stat_obj

    _fix_sudo_permissions("/fake/rootfs")

    # Verify os.chown was called for targets
    assert mock_chown.call_count >= 4
    mock_chown.assert_any_call("/fake/rootfs/usr/bin/sudo", 0, 0)
    mock_chown.assert_any_call("/fake/rootfs/etc/sudoers", 0, 0)

    # Verify os.chmod was called only for paths with mismatched permissions
    # sudo (needs 4755 != 644) and sudoers (needs 440 != 644)
    assert mock_chmod.call_count == 2
    mock_chmod.assert_any_call("/fake/rootfs/usr/bin/sudo", 0o4755)
    mock_chmod.assert_any_call("/fake/rootfs/etc/sudoers", 0o440)


def test_get_bindings_home_sharing():
    from chroot_distro.commands.login.bindings import get_bindings

    # 1. With login_home="/root", it should automatically share the home directory
    with patch("os.path.exists", return_value=True), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_home=False,
            login_home="/root"
        )
        # Check that "/root" is bind-mounted (mapped to rootfs path)
        home_binds = [dst for src, dst in binds if dst.endswith("/root")]
        assert len(home_binds) == 1

    # 2. With login_home="/home/saba", it should NOT automatically share the home directory
    # unless shared_home=True is explicitly passed.
    with patch("os.path.exists", return_value=True), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_home=False,
            login_home="/home/saba"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/home/saba")]
        assert len(home_binds) == 0

    # 3. With login_home="/home/saba" and shared_home=True, it should share it
    with patch("os.path.exists", return_value=True), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_home=True,
            login_home="/home/saba"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/home/saba")]
        assert len(home_binds) == 1
