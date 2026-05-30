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

    assert args[0].endswith("chroot")
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


def test_build_chroot_args_termux_chroot_resolution():
    with patch("chroot_distro.commands.login.chroot_cmd.IS_TERMUX", True), \
         patch("chroot_distro.commands.login.chroot_cmd.TERMUX_PREFIX", "/fake/termux/usr"), \
         patch("os.path.isfile", side_effect=lambda p: p == "/fake/termux/usr/bin/chroot"):
        args = build_chroot_args(rootfs="/fake/rootfs")
        assert args[0] == "/fake/termux/usr/bin/chroot"


def test_special_mounts_default():
    from chroot_distro.commands.login.bindings import get_special_mounts
    
    with patch("os.path.exists", return_value=False), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        specials = get_special_mounts("/fake/rootfs")
        
        # In non-Termux/Linux by default, it should at least return devpts
        assert len(specials) >= 1
        devpts_mount = [s for s in specials if s.fstype == "devpts"]
        assert len(devpts_mount) == 1
        assert devpts_mount[0].target == "/dev/pts"
        assert devpts_mount[0].optional is False


def test_special_mounts_termux_all():
    from chroot_distro.commands.login.bindings import get_special_mounts
    
    with patch("os.path.exists", return_value=False), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", True), \
         patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True), \
         patch("os.path.isdir", return_value=False), \
         patch("os.listdir", return_value=["usb1"]):
        specials = get_special_mounts("/fake/rootfs")
        
        # On Termux with support and USB OTG active, it should mount all specials
        fstypes = [s.fstype for s in specials]
        assert "devpts" in fstypes
        assert "usbfs" in fstypes
        assert "binfmt_misc" in fstypes
        assert "cgroup" in fstypes
        assert "tmpfs" in fstypes


def test_get_bindings_shared_tmp_termux():
    from chroot_distro.commands.login.bindings import get_bindings, TERMUX_PREFIX

    # 1. Termux environment with shared_tmp=True, dist_type="normal"
    with patch("os.path.exists", return_value=True), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", True):
        binds = get_bindings(
            rootfs="/fake/rootfs",
            shared_tmp=True,
            dist_type="normal"
        )
        # Should map host TERMUX_PREFIX/tmp to container /tmp
        expected_src = f"{TERMUX_PREFIX}/tmp"
        expected_dst = "/fake/rootfs/tmp"
        assert (expected_src, expected_dst) in binds

    # 2. Termux environment with shared_x11=True, dist_type="normal"
    with patch("os.path.exists", return_value=True), \
         patch("chroot_distro.commands.login.bindings.IS_TERMUX", True):
        binds = get_bindings(
            rootfs="/fake/rootfs",
            shared_x11=True,
            dist_type="normal"
        )
        # Should map host TERMUX_PREFIX/tmp/.X11-unix to container /tmp/.X11-unix
        expected_src = f"{TERMUX_PREFIX}/tmp/.X11-unix"
        expected_dst = "/fake/rootfs/tmp/.X11-unix"
        assert (expected_src, expected_dst) in binds


