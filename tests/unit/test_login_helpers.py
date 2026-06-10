import os
from unittest.mock import patch

from chroot_distro.commands.login.chroot_cmd import build_chroot_args
from chroot_distro.commands.login.env import resolve_term


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


def test_build_chroot_args_fault_tolerant_cd(tmp_path):
    # Test that when a workdir is specified AND /bin/sh exists, it wraps the command with a fault-tolerant cd.
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "sh").touch()
    (rootfs / "bin" / "sh").chmod(0o755)

    args = build_chroot_args(
        rootfs=str(rootfs),
        login_uid="1000",
        login_gid="1000",
        groups=["1000", "4"],
        workdir="/home/saba",
        inner_cmd=["/bin/bash", "-l"],
    )

    assert args[0].endswith("chroot")
    assert "--userspec=1000:1000" in args
    assert "--groups=1000,4" in args
    assert str(rootfs) in args

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
        inner_cmd=["/bin/bash", "-l"],
    )
    # When no workdir is specified, it should NOT wrap it with cd.
    assert "/bin/sh" not in args
    assert args[-2:] == ["/bin/bash", "-l"]


def test_build_chroot_args_distroless_no_shell(tmp_path):
    """Distroless images without /bin/sh should skip the cd wrapper."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    # No /bin/sh created — simulates a distroless image like cloudflare/cloudflared

    args = build_chroot_args(
        rootfs=str(rootfs),
        login_uid="65532",
        login_gid="65532",
        workdir="/home/nonroot",
        inner_cmd=["/usr/local/bin/cloudflared", "--help"],
    )

    assert args[0].endswith("chroot")
    assert str(rootfs) in args
    # /bin/sh should NOT be in the args — no shell wrapper
    assert "/bin/sh" not in args
    assert "-c" not in args
    # The command should be appended directly
    assert args[-2:] == ["/usr/local/bin/cloudflared", "--help"]


def test_build_chroot_args_distroless_workdir_root(tmp_path):
    """Distroless images with workdir='/' should not attempt any wrapping."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    args = build_chroot_args(
        rootfs=str(rootfs),
        workdir="/",
        inner_cmd=["/cloudflared", "tunnel"],
    )

    assert "/bin/sh" not in args
    assert args[-2:] == ["/cloudflared", "tunnel"]


def test_get_bindings_home_sharing():
    from chroot_distro.commands.login.bindings import get_bindings

    # 1. Root without --shared-home: no host home bind (matches proot-distro)
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs", minimal=False, isolated=False, shared_home=False, login_home="/root"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/root")]
        assert len(home_binds) == 0

    # 1b. Root with --shared-home: host home bind-mounted to /root
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs", minimal=False, isolated=False, shared_home=True, login_home="/root"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/root")]
        assert len(home_binds) == 1

    # 2. With login_home="/home/saba", it should NOT automatically share the home directory
    # unless shared_home=True is explicitly passed.
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs", minimal=False, isolated=False, shared_home=False, login_home="/home/saba"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/home/saba")]
        assert len(home_binds) == 0

    # 3. With login_home="/home/saba" and shared_home=True, it should share it
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs", minimal=False, isolated=False, shared_home=True, login_home="/home/saba"
        )
        home_binds = [dst for src, dst in binds if dst.endswith("/home/saba")]
        assert len(home_binds) == 1

    # 4. On Termux with --shared-home, bind TERMUX_HOME onto the guest passwd home
    termux_home = "/data/data/com.termux/files/home"
    guest_home = "/home/saba"
    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings.TERMUX_HOME", termux_home),
        patch("chroot_distro.commands.login.bindings.system_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.storage_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.android_data_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.TERMUX_PREFIX", "/data/data/com.termux/files/usr"),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_home=True,
            login_home=guest_home,
        )
        termux_binds = [(src, dst) for src, dst in binds if src == termux_home and dst.endswith("/home/saba")]
        assert len(termux_binds) == 1
        data_binds = [(src, dst) for src, dst in binds if src == "/data" and dst.endswith("data")]
        assert len(data_binds) == 1


def test_resolve_host_home_uses_sudo_user_not_container_name():
    from chroot_distro.commands.login.passwd import resolve_host_home

    with (
        patch("os.getuid", return_value=0),
        patch.dict(
            os.environ,
            {
                "HOME": "/root",
                "USER": "root",
                "SUDO_USER": "sabamdarif",
            },
            clear=False,
        ),
        patch("pwd.getpwnam", side_effect=lambda n: type("pw", (), {"pw_dir": f"/host/home/{n}"})()),
    ):
        assert resolve_host_home("saba") == "/host/home/sabamdarif"
        assert resolve_host_home("root") == "/root"


def test_resolve_host_home_returns_none_for_unknown_guest_user():
    from chroot_distro.commands.login.passwd import resolve_host_home

    with (
        patch("os.getuid", return_value=0),
        patch.dict(os.environ, {"HOME": "/root", "USER": "root"}, clear=False),
        patch("pwd.getpwnam", side_effect=KeyError("missing")),
    ):
        assert resolve_host_home("saba") is None
        assert resolve_host_home("root") == "/root"


def test_sync_passwd_to_path_owner(tmp_path):
    from chroot_distro.commands.login.passwd import sync_passwd_to_path_owner

    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    host_dir = tmp_path / "hosthome"
    host_dir.mkdir()
    uid, gid = os.getuid(), os.getgid()
    os.chown(host_dir, uid, gid)
    (etc / "passwd").write_text(
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nsaba:x:1001:1001:Saba:/home/saba:/bin/bash\n",
        encoding="utf-8",
    )
    assert sync_passwd_to_path_owner(str(rootfs), "saba", str(host_dir))
    passwd = (etc / "passwd").read_text(encoding="utf-8")
    assert f"saba:x:{uid}:{gid}:" in passwd
    assert f"ubuntu:x:{uid}:{gid}:" not in passwd


def test_sync_passwd_to_path_owner_skips_root(tmp_path):
    from chroot_distro.commands.login.passwd import sync_passwd_to_path_owner

    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    host_dir = tmp_path / "hosthome"
    host_dir.mkdir()
    os.chown(host_dir, os.getuid(), os.getgid())
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n",
        encoding="utf-8",
    )
    assert not sync_passwd_to_path_owner(str(rootfs), "root", str(host_dir))
    assert (etc / "passwd").read_text(encoding="utf-8") == ("root:x:0:0:root:/root:/bin/bash\n")


def test_release_passwd_uid_conflicts(tmp_path):
    from chroot_distro.commands.login.passwd import (
        release_passwd_uid_conflicts,
        set_passwd_uid_gid,
    )

    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text(
        "root:x:1000:1000:root:/root:/bin/bash\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "saba:x:1001:1001:Saba:/home/saba:/bin/bash\n",
        encoding="utf-8",
    )
    uid, gid = 1000, 1000
    set_passwd_uid_gid(str(rootfs), "saba", uid, gid)
    release_passwd_uid_conflicts(str(rootfs), "saba", uid, gid)
    passwd = (etc / "passwd").read_text(encoding="utf-8")
    assert f"saba:x:{uid}:{gid}:" in passwd
    assert "root:x:0:0:" in passwd
    assert f"ubuntu:x:{uid}:{gid}:" not in passwd


def test_sync_passwd_to_home_owner(tmp_path):
    from chroot_distro.commands.login.passwd import sync_passwd_to_home_owner

    rootfs = tmp_path / "rootfs"
    home = rootfs / "home" / "saba"
    home.mkdir(parents=True)
    uid, gid = os.getuid(), os.getgid()
    os.chown(home, uid, gid)
    etc = rootfs / "etc"
    etc.mkdir()
    (etc / "passwd").write_text(
        "saba:x:10328:10328:Saba:/home/saba:/bin/bash\n",
        encoding="utf-8",
    )
    assert sync_passwd_to_home_owner(str(rootfs), "saba", "/home/saba")
    passwd = (etc / "passwd").read_text(encoding="utf-8")
    assert f"saba:x:{uid}:{gid}:" in passwd


def test_align_user_to_termux_owner(tmp_path):
    from chroot_distro.commands.login.passwd import align_user_to_termux_owner

    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nsaba:x:1000:1000:Saba:/home/saba:/bin/bash\n",
        encoding="utf-8",
    )
    (etc / "shadow").write_text(
        "root:*:1::::::\nsaba:*:1::::::\n",
        encoding="utf-8",
    )
    assert align_user_to_termux_owner(str(rootfs), "saba", 10328, 10328)
    passwd = (etc / "passwd").read_text(encoding="utf-8")
    assert "saba:x:10328:10328:" in passwd
    shadow = (etc / "shadow").read_text(encoding="utf-8")
    assert shadow.startswith("root:")
    assert "saba:*:10328:10328:" in shadow


def test_termux_home_owner_ids(tmp_path):
    from chroot_distro.helpers.android import termux_home_owner_ids

    home = tmp_path / "home"
    home.mkdir()
    uid, gid = os.getuid(), os.getgid()
    os.chown(home, uid, gid)
    with patch("chroot_distro.helpers.android.TERMUX_HOME", str(home)):
        assert termux_home_owner_ids() == (uid, gid)


def test_ensure_data_suid_skips_when_already_suid():
    from chroot_distro.helpers.android import ensure_data_suid

    with (
        patch("chroot_distro.helpers.android.IS_TERMUX", True),
        patch(
            "chroot_distro.helpers.android._read_data_mount",
            return_value=("tmpfs", "/data", "rw,seclabel,suid"),
        ),
    ):
        assert ensure_data_suid() is True


def test_build_chroot_args_termux_chroot_resolution():
    with (
        patch("chroot_distro.commands.login.chroot_cmd.IS_TERMUX", True),
        patch("chroot_distro.commands.login.chroot_cmd.TERMUX_PREFIX", "/fake/termux/usr"),
        patch("os.path.isfile", side_effect=lambda p: p == "/fake/termux/usr/bin/chroot"),
    ):
        args = build_chroot_args(rootfs="/fake/rootfs")
        assert args[0] == "/fake/termux/usr/bin/chroot"


def test_special_mounts_default():
    from chroot_distro.commands.login.bindings import get_special_mounts

    with patch("os.path.exists", return_value=False), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        specials = get_special_mounts("/fake/rootfs")

        # In non-Termux/Linux by default, it should at least return devpts
        assert len(specials) >= 1
        assert not any(s.fstype == "proc" for s in specials)
        devpts_mount = [s for s in specials if s.fstype == "devpts"]
        assert len(devpts_mount) == 1
        assert devpts_mount[0].target == "/dev/pts"
        assert devpts_mount[0].optional is False


def test_special_mounts_isolated_includes_proc():
    from chroot_distro.commands.login.bindings import get_special_mounts

    with (
        patch("os.path.exists", return_value=False),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True),
    ):
        specials = get_special_mounts("/fake/rootfs", isolated=True)
        proc_mounts = [s for s in specials if s.fstype == "proc"]
        assert len(proc_mounts) == 1
        assert proc_mounts[0].target == "/proc"
        assert proc_mounts[0].optional is False
        assert specials[0].fstype == "proc"


def test_special_mounts_termux_all():
    from chroot_distro.commands.login.bindings import get_special_mounts

    with (
        patch("os.path.exists", return_value=False),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True),
        patch("os.path.isdir", return_value=False),
        patch("os.listdir", return_value=["usb1"]),
    ):
        specials = get_special_mounts("/fake/rootfs")

        # On Termux with support and USB OTG active, it should mount all specials
        fstypes = [s.fstype for s in specials]
        assert "devpts" in fstypes
        assert "usbfs" in fstypes
        assert "binfmt_misc" in fstypes
        assert "cgroup" in fstypes
        assert "tmpfs" in fstypes


def test_get_bindings_isolated_linux():
    from chroot_distro.commands.login.bindings import get_bindings

    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=True,
            shared_tmp=False,
            shared_display=False,
        )
        srcs = {src for src, _ in binds}
        assert "/proc" not in srcs
        assert "/tmp" not in srcs
        assert "/tmp/.X11-unix" not in srcs

        binds_tmp, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=True,
            shared_tmp=True,
        )
        tmp_binds = [src for src, _ in binds_tmp if src == "/tmp"]
        assert len(tmp_binds) == 1


def test_get_bindings_minimal_linux():
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch("chroot_distro.commands.login.bindings.host_resolv_conf_path", return_value="/etc/resolv.conf"),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=True,
            isolated=False,
        )
        srcs = {src for src, _ in binds}
        assert "/tmp" not in srcs
        assert "/dev" in srcs
        assert "/proc" in srcs
        assert "/sys" in srcs
        assert ("/etc/resolv.conf", "/fake/rootfs/etc/resolv.conf") in binds


def test_get_bindings_termux_resolv_bind():
    from chroot_distro.commands.login.bindings import TERMUX_PREFIX, get_bindings

    host_resolv = f"{TERMUX_PREFIX}/etc/resolv.conf"
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings.system_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.storage_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.android_data_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.host_resolv_conf_path", return_value=host_resolv),
    ):
        binds, _ = get_bindings(rootfs="/fake/rootfs", minimal=False, isolated=False)
        assert (host_resolv, "/fake/rootfs/etc/resolv.conf") in binds


def test_get_bindings_shared_tmp_termux():
    from chroot_distro.commands.login.bindings import TERMUX_PREFIX, get_bindings

    # 1. Termux environment with shared_tmp=True, dist_type="normal"
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", True):
        binds, _ = get_bindings(rootfs="/fake/rootfs", shared_tmp=True, dist_type="normal")
        # Should map host TERMUX_PREFIX/tmp to container /tmp
        expected_src = f"{TERMUX_PREFIX}/tmp"
        expected_dst = "/fake/rootfs/tmp"
        assert (expected_src, expected_dst) in binds

    # 2. Termux environment with shared_display=True, dist_type="normal"
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", True):
        binds, _ = get_bindings(rootfs="/fake/rootfs", shared_display=True, dist_type="normal")
        # Should map host TERMUX_PREFIX/tmp/.X11-unix to container /tmp/.X11-unix
        expected_src = f"{TERMUX_PREFIX}/tmp/.X11-unix"
        expected_dst = "/fake/rootfs/tmp/.X11-unix"
        assert (expected_src, expected_dst) in binds
