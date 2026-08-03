import os
from types import SimpleNamespace
from unittest.mock import patch

from chroot_distro.commands.login import (
    _can_fall_back_to_old_isolated,
    _command_login_inner,
    _MaxIsolationFallback,
    _safe_hostname,
)
from chroot_distro.commands.login.chroot_cmd import build_chroot_args
from chroot_distro.commands.login.env import read_cd_env, resolve_override, resolve_term


def test_safe_hostname_valid_tokens():
    assert _safe_hostname("alpine") == "alpine"
    assert _safe_hostname("web-01") == "web-01"
    assert _safe_hostname("a.b.c") == "a.b.c"


def test_safe_hostname_rejects_underscore_and_empty():
    # underscores are valid container names but not safe hostnames
    assert _safe_hostname("my_box") == "localhost"
    assert _safe_hostname("") == "localhost"


def test_safe_hostname_rejects_overlong_label():
    assert _safe_hostname("a" * 64) == "localhost"
    # each label must be <= 63 even if the whole string is longer
    assert _safe_hostname("ok." + "b" * 64) == "localhost"


def test_can_fall_back_only_on_termux_max_isolation_once():
    """Fallback is allowed only on Termux, only under max isolation, and only
    until the one-shot opt-out flag is set."""
    import chroot_distro.commands.login as login_mod

    with patch.object(login_mod, "IS_TERMUX", True):
        # Eligible: Termux + max isolation + not yet retried.
        assert _can_fall_back_to_old_isolated(True, SimpleNamespace()) is True
        # Not eligible once the opt-out has been set (prevents a retry loop).
        assert (
            _can_fall_back_to_old_isolated(
                True, SimpleNamespace(_disable_max_isolation=True)
            )
            is False
        )
        # Not eligible when max isolation is already off.
        assert _can_fall_back_to_old_isolated(False, SimpleNamespace()) is False

    # Never eligible on a non-Termux (real Linux) host: keep refusing there.
    with patch.object(login_mod, "IS_TERMUX", False):
        assert _can_fall_back_to_old_isolated(True, SimpleNamespace()) is False


def test_command_login_inner_retries_once_on_fallback():
    """The wrapper retries the login exactly once with max isolation disabled
    when the inner run raises _MaxIsolationFallback, then propagates a second
    failure unchanged."""
    import chroot_distro.commands.login as login_mod

    calls = []

    def fake_once(container_name, args):
        calls.append(getattr(args, "_disable_max_isolation", False))
        if len(calls) == 1:
            raise _MaxIsolationFallback("selinux denied tmpfs /dev")
        # Second call (fallback) succeeds.

    args = SimpleNamespace()
    with (
        patch.object(login_mod, "_command_login_inner_once", side_effect=fake_once),
        patch.object(login_mod, "warn"),
    ):
        _command_login_inner("debian", args)

    assert calls == [False, True]
    assert args._disable_max_isolation is True


def test_command_login_inner_does_not_retry_twice():
    """A second _MaxIsolationFallback (should not normally happen, since the
    retry disables max isolation) is not swallowed into an infinite loop."""
    import chroot_distro.commands.login as login_mod

    calls = []

    def always_fallback(container_name, args):
        calls.append(True)
        raise _MaxIsolationFallback("still failing")

    with (
        patch.object(login_mod, "_command_login_inner_once", side_effect=always_fallback),
        patch.object(login_mod, "warn"),
    ):
        try:
            _command_login_inner("debian", SimpleNamespace())
            raised = False
        except _MaxIsolationFallback:
            raised = True

    # Wrapper only catches the first; the second propagates (no infinite loop).
    assert raised is True
    assert len(calls) == 2


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


def test_build_chroot_args_shell_symlink_escapes_rootfs(tmp_path):
    """A /bin/sh symlink pointing outside the rootfs must not be used as the
    workdir wrapper shell (e.g. bind-mounted host $PREFIX on Termux). The
    command should then be run directly without a shell wrapper."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    outside = tmp_path / "host_usr" / "bin"
    outside.mkdir(parents=True)
    (outside / "sh").touch()
    (outside / "sh").chmod(0o755)
    # /bin/sh in the rootfs is a symlink to a file *outside* the rootfs tree.
    os.symlink(str(outside / "sh"), rootfs / "bin" / "sh")

    args = build_chroot_args(
        rootfs=str(rootfs),
        workdir="/home/nonroot",
        inner_cmd=["/app", "--help"],
    )
    assert "/bin/sh" not in args
    assert "-c" not in args
    assert args[-2:] == ["/app", "--help"]


def test_build_chroot_args_run_skips_workdir_wrapper(tmp_path):
    """For `run` (is_run=True), a non-root workdir must NOT wrap the command in
    a shell, even when a real /bin/sh exists in the rootfs (which on Termux can
    be the host $PREFIX shell exposed via a bind-mounted /data)."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "sh").touch()
    (rootfs / "bin" / "sh").chmod(0o755)

    args = build_chroot_args(
        rootfs=str(rootfs),
        workdir="/home/nonroot",
        inner_cmd=["/usr/local/bin/cloudflared", "--help"],
        is_run=True,
    )

    assert "/bin/sh" not in args
    assert "-c" not in args
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
        patch("chroot_distro.commands.login.bindings.dalvik_cache_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.termux_app_bindings", return_value=[]),
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


def test_build_termux_env_scrubs_linker_preloads():
    from chroot_distro.commands.login import _build_termux_env

    env = _build_termux_env(
        "/fake/rootfs",
        "/fake/container",
        ["LD_PRELOAD=/host/libtermux-exec.so", "LD_LIBRARY_PATH=/host/lib", "FOO=bar"],
        minimal=False,
        isolated=False,
    )
    assert "LD_PRELOAD" not in env
    assert "LD_LIBRARY_PATH" not in env
    assert env["FOO"] == "bar"
    assert env["ANDROID_DATA"] == "/data"
    assert env["ANDROID_ROOT"] == "/system"
    assert env["LANG"] == "en_US.UTF-8"


def test_build_termux_env_minimal_still_scrubs_preloads():
    from chroot_distro.commands.login import _build_termux_env

    env = _build_termux_env(
        "/fake/rootfs",
        "/fake/container",
        ["LD_PRELOAD=/host/libtermux-exec.so"],
        minimal=True,
        isolated=False,
    )
    assert "LD_PRELOAD" not in env
    # minimal mode does not inject the android entrypoint vars
    assert "ANDROID_DATA" not in env


def test_build_termux_env_never_sets_ld_preload_even_with_guest_shim(tmp_path):
    """Even when a guest libtermux-exec shim exists in the rootfs, the chroot
    must be entered WITHOUT LD_PRELOAD. A stale/host-prefixed preload
    the guest linker cannot resolve triggers the "helper program for dynamic
    executables" banner."""
    from chroot_distro.commands.login import TERMUX_PREFIX, _build_termux_env

    rootfs = tmp_path / "rootfs"
    lib_dir = rootfs / TERMUX_PREFIX.lstrip("/") / "lib"
    lib_dir.mkdir(parents=True)
    (lib_dir / "libtermux-exec-ld-preload.so").touch()

    env = _build_termux_env(
        str(rootfs),
        "/fake/container",
        ["LD_PRELOAD=/host/libtermux-exec-ld-preload.so", "LD_LIBRARY_PATH=/host/lib"],
        minimal=False,
        isolated=False,
    )
    assert "LD_PRELOAD" not in env
    assert "LD_LIBRARY_PATH" not in env


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


def test_sync_passwd_to_path_owner_repairs_stale_root(tmp_path):
    """Regression (Termux): a previous --shared-home bind left root's passwd
    uid/gid remapped to the Termux app uid even though /root on disk is
    root-owned. The next plain login must repair root back to 0:0 so the
    guest can read its own $HOME."""
    from chroot_distro.commands.login.passwd import sync_passwd_to_path_owner

    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text(
        "root:x:10328:10328:root:/root:/bin/bash\n",
        encoding="utf-8",
    )
    host_dir = tmp_path / "root_home"
    host_dir.mkdir()
    assert sync_passwd_to_path_owner(str(rootfs), "root", str(host_dir))
    assert (etc / "passwd").read_text(encoding="utf-8") == ("root:x:0:0:root:/root:/bin/bash\n")


def test_sync_passwd_to_home_owner_repairs_stale_root(tmp_path):
    """End-to-end: resolve the in-rootfs /root and repair the stale root
    passwd entry left behind by a Termux --shared-home session."""
    from chroot_distro.commands.login.passwd import sync_passwd_to_home_owner

    rootfs = tmp_path / "rootfs"
    home = rootfs / "root"
    home.mkdir(parents=True)
    etc = rootfs / "etc"
    etc.mkdir()
    (etc / "passwd").write_text(
        "root:x:10328:10328:root:/root:/bin/bash\n",
        encoding="utf-8",
    )
    assert sync_passwd_to_home_owner(str(rootfs), "root", "/root")
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
        assert any(s.fstype == "proc" for s in specials)
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
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=True,
            isolated=False,
        )
        srcs = {src for src, _ in binds}
        assert "/tmp" not in srcs
        assert "/dev" in srcs
        assert "/proc" not in srcs
        assert "/sys" in srcs


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


def test_get_bindings_termux_dist_type():
    from chroot_distro.commands.login.bindings import TERMUX_PREFIX, get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings.system_bindings", return_value=[("/system", "/system")]),
        patch("chroot_distro.commands.login.bindings.storage_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.dalvik_cache_bindings", return_value=[]),
        patch(
            "chroot_distro.commands.login.bindings.termux_app_bindings",
            return_value=[("/data/data/com.termux/cache", "/data/data/com.termux/cache")],
        ),
    ):
        binds, _ = get_bindings(rootfs="/fake/rootfs", minimal=False, isolated=False, dist_type="termux")
        srcs = {src for src, _ in binds}
        dsts = {dst for _, dst in binds}

        # Check that TERMUX_PREFIX and /data are skipped for termux-type containers
        assert f"/fake/rootfs{TERMUX_PREFIX}" not in dsts
        assert "/data" not in srcs

        # Check that system_bindings ARE included (needed for termux-exec to work on Android hosts)
        assert "/system" in srcs

        # Check that termux app cache bindings are skipped (termux-type has its own)
        assert "/data/data/com.termux/cache" not in srcs


def test_custom_bind_overrides_data_on_termux():
    """Custom --bind src:/data should override the system /data mount on Termux."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings.system_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.storage_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.dalvik_cache_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.termux_app_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.TERMUX_PREFIX", "/data/data/com.termux/files/usr"),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/home/user/matter-data:/data"],
        )
        # The user's custom bind should be present
        data_binds = [(src, dst) for src, dst in binds if dst == "/fake/rootfs/data"]
        assert len(data_binds) == 1
        assert data_binds[0][0] == "/home/user/matter-data"


def test_custom_bind_overrides_tmp_on_linux():
    """Custom --bind src:/tmp should override the system /tmp mount on Linux."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/my/tmp:/tmp"],
        )
        tmp_binds = [(src, dst) for src, dst in binds if dst == "/fake/rootfs/tmp"]
        assert len(tmp_binds) == 1
        assert tmp_binds[0][0] == "/my/tmp"


def test_custom_bind_blocks_dev():
    """Custom --bind src:/dev should be blocked (critical pseudo-filesystem)."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/my/dev:/dev"],
        )
        dev_binds = [(src, dst) for src, dst in binds if src == "/my/dev"]
        assert len(dev_binds) == 0
        # System /dev bind should still be present
        sys_dev = [(src, dst) for src, dst in binds if src == "/dev" and dst == "/fake/rootfs/dev"]
        assert len(sys_dev) == 1


def test_custom_bind_blocks_proc():
    """Custom --bind src:/proc should be blocked (critical pseudo-filesystem)."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/my/proc:/proc"],
        )
        proc_binds = [(src, dst) for src, dst in binds if src == "/my/proc"]
        assert len(proc_binds) == 0


def test_custom_bind_skips_nonexistent_source(tmp_path):
    """Custom --bind with non-existent source path should be skipped."""
    from chroot_distro.commands.login.bindings import get_bindings

    nonexistent = str(tmp_path / "does_not_exist")

    with (
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=[f"{nonexistent}:/mnt/data"],
        )
        custom = [(src, dst) for src, dst in binds if src == nonexistent]
        assert len(custom) == 0


def test_custom_bind_no_conflict_passes_through():
    """Custom --bind to a non-conflicting path should work normally."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/host/mydir:/mnt/mydir"],
        )
        custom = [(src, dst) for src, dst in binds if src == "/host/mydir"]
        assert len(custom) == 1
        assert custom[0][1] == "/fake/rootfs/mnt/mydir"


def test_custom_bind_removes_nested_system_binds_on_termux():
    """Custom --bind src:/data should remove all default system binds nested under /data on Termux."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", True),
        patch("chroot_distro.commands.login.bindings.system_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.storage_bindings", return_value=[]),
        patch(
            "chroot_distro.commands.login.bindings.dalvik_cache_bindings",
            return_value=[
                ("/data/dalvik-cache", "/data/dalvik-cache"),
                (
                    "/data/misc/apexdata/com.android.art/dalvik-cache",
                    "/data/misc/apexdata/com.android.art/dalvik-cache",
                ),
            ],
        ),
        patch("chroot_distro.commands.login.bindings.termux_app_bindings", return_value=[]),
        patch("chroot_distro.commands.login.bindings.TERMUX_PREFIX", "/data/data/com.termux/files/usr"),
    ):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            custom_binds=["/home/user/matter-data:/data"],
        )
        # Verify the main custom bind is present
        data_binds = [(src, dst) for src, dst in binds if dst == "/fake/rootfs/data"]
        assert len(data_binds) == 1
        assert data_binds[0][0] == "/home/user/matter-data"

        # Verify that nested binds are removed
        nested_binds = [dst for src, dst in binds if dst.startswith("/fake/rootfs/data/")]
        assert len(nested_binds) == 0


def test_resolve_rootfs_path_basic(tmp_path):
    from chroot_distro.commands.login.passwd import resolve_rootfs_path

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    # Case 1: Simple existing file path
    etc = rootfs / "etc"
    etc.mkdir()
    passwd = etc / "passwd"
    passwd.touch()

    res = resolve_rootfs_path(str(rootfs), "/etc/passwd")
    assert res == os.path.realpath(str(passwd))

    # Case 2: Simple non-existing path
    res2 = resolve_rootfs_path(str(rootfs), "/etc/nonexistent")
    assert res2 == os.path.join(os.path.realpath(str(rootfs)), "etc", "nonexistent")


def test_resolve_rootfs_path_symlinks(tmp_path):
    from chroot_distro.commands.login.passwd import resolve_rootfs_path

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    # Setup directories
    (rootfs / "usr" / "bin").mkdir(parents=True)
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "etc").mkdir(parents=True)

    # 1. Relative symlink to non-existing target (broken symlink)
    # Target of symlink system is relative: data/data/com.termux/files/usr/opt/aosp
    os.symlink("data/data/com.termux/files/usr/opt/aosp", rootfs / "system")
    res = resolve_rootfs_path(str(rootfs), "/system")
    # Should resolve to: <rootfs>/data/data/com.termux/files/usr/opt/aosp
    expected = os.path.join(os.path.realpath(str(rootfs)), "data", "data", "com.termux", "files", "usr", "opt", "aosp")
    assert res == expected

    # 2. Relative symlink with `..` that tries to escape rootfs
    # /etc/badlink -> ../../../etc/passwd (should remain inside rootfs/etc/passwd)
    (rootfs / "etc" / "passwd").touch()
    os.symlink("../../../etc/passwd", rootfs / "etc" / "badlink")
    res2 = resolve_rootfs_path(str(rootfs), "/etc/badlink")
    expected2 = os.path.join(os.path.realpath(str(rootfs)), "etc", "passwd")
    assert res2 == expected2

    # 3. Absolute symlink in rootfs (jail-locked)
    # /bin/sh -> /usr/bin/bash (should resolve to <rootfs>/usr/bin/bash)
    os.symlink("/usr/bin/bash", rootfs / "bin" / "sh")
    res3 = resolve_rootfs_path(str(rootfs), "/bin/sh")
    expected3 = os.path.join(os.path.realpath(str(rootfs)), "usr", "bin", "bash")
    assert res3 == expected3

    # 4. Nested symlinks
    # /usr/bin/python -> python3 -> python3.10
    # python3.10 doesn't exist.
    os.symlink("python3", rootfs / "usr" / "bin" / "python")
    os.symlink("python3.10", rootfs / "usr" / "bin" / "python3")
    res4 = resolve_rootfs_path(str(rootfs), "/usr/bin/python")
    expected4 = os.path.join(os.path.realpath(str(rootfs)), "usr", "bin", "python3.10")
    assert res4 == expected4


def test_get_bindings_max_isolation_binds_nothing():
    """--isolated (max_isolation) must produce zero host bind mounts so the
    container has no host path to traverse (e.g. via chroot /proc/1/root)."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=True,
            max_isolation=True,
            use_namespaces=True,
            shared_home=True,
            shared_tmp=True,
            shared_display=True,
            custom_binds=["/host/x:/mnt/x"],
        )
        assert binds == []
        assert rslave == []


def test_get_bindings_default_does_not_bind_host_proc():
    """Default (no-flag) mode must no longer bind-mount the host /proc; a fresh
    procfs is mounted by get_special_mounts() instead."""
    from chroot_distro.commands.login.bindings import get_bindings

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, _rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            use_namespaces=False,
        )
    sources = {src for src, _dst in binds}
    assert "/proc" not in sources
    # /dev and /sys are still bound in the default mode.
    assert "/dev" in sources
    assert "/sys" in sources


def test_special_mounts_default_mode_mounts_fresh_procfs():
    """Even in the default (non-isolated, no-namespace) mode a fresh procfs is
    now mounted, with no hidepid hardening (that is max-isolation only)."""
    from chroot_distro.commands.login.bindings import get_special_mounts

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True),
    ):
        specials = get_special_mounts("/fake/rootfs", isolated=False, max_isolation=False)

    proc = [s for s in specials if s.fstype == "proc" and s.target == "/proc"]
    assert len(proc) == 1
    assert proc[0].optional is False
    assert "hidepid" not in proc[0].options


def test_special_mounts_max_isolation_fresh_pseudo_fs():
    """Under max isolation, get_special_mounts must synthesise a fresh /dev
    tmpfs, a read-only sysfs, a fresh procfs and a fresh /dev/shm."""
    from chroot_distro.commands.login.bindings import get_special_mounts

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True),
    ):
        specials = get_special_mounts("/fake/rootfs", isolated=True, max_isolation=True)

    dev = [s for s in specials if s.fstype == "tmpfs" and s.target == "/dev"]
    assert len(dev) == 1
    assert dev[0].optional is False

    sysfs = [s for s in specials if s.fstype == "sysfs" and s.target == "/sys"]
    assert len(sysfs) == 1
    assert "ro" in sysfs[0].options

    proc = [s for s in specials if s.fstype == "proc" and s.target == "/proc"]
    assert len(proc) == 1
    assert proc[0].optional is False

    shm = [s for s in specials if s.fstype == "tmpfs" and s.target == "/dev/shm"]
    assert len(shm) == 1


def test_filter_flags_by_ns_files_drops_unopenable_cgroup():
    """A flag whose /proc/<pid>/ns/<name> cannot be opened must be dropped,
    mirroring Android kernels where nsenter fails to open the cgroup ns."""
    from chroot_distro.helpers import namespace as ns

    flags = ["--mount", "--uts", "--ipc", "--pid", "--cgroup"]

    def fake_open(path, *a, **k):
        if path.endswith("/ns/cgroup"):
            raise OSError(2, "No such file or directory")
        return 99

    with patch.object(ns.os, "open", side_effect=fake_open), patch.object(ns.os, "close"):
        kept = ns.filter_flags_by_ns_files(1234, flags)
    assert "--cgroup" not in kept
    assert kept == ["--mount", "--uts", "--ipc", "--pid"]


def test_filter_flags_by_ns_files_keeps_all_when_openable():
    from chroot_distro.helpers import namespace as ns

    flags = ["--mount", "--pid", "--cgroup"]
    with patch.object(ns.os, "open", return_value=7), patch.object(ns.os, "close"):
        assert ns.filter_flags_by_ns_files(1, flags) == flags


def test_holder_run_argv_drops_unopenable_ipc_at_call_time():
    """run_argv must drop a namespace whose ns file is unopenable right now,
    but always keep the essential mount namespace."""
    from chroot_distro.helpers import namespace as ns
    from chroot_distro.syscalls._constants import CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS

    holder = ns.NamespaceHolder(
        pid=4321,
        ns_flags=CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID,
        container_name="debian",
    )

    def fake_open(path, *a, **k):
        if path.endswith("/ns/ipc"):
            raise OSError(2, "No such file or directory")
        return 5

    with patch.object(ns.os, "open", side_effect=fake_open), patch.object(ns.os, "close"):
        argv = holder.run_argv(["true"])

    assert "--ipc" not in argv
    assert "--mount" in argv
    assert "--pid" in argv and "--uts" in argv
    assert argv[:3] == ["nsenter", "--target", "4321"]


def test_holder_run_argv_keeps_mount_even_if_unopenable():
    from chroot_distro.helpers import namespace as ns
    from chroot_distro.syscalls._constants import CLONE_NEWNS

    holder = ns.NamespaceHolder(
        pid=1,
        ns_flags=CLONE_NEWNS,
        container_name="x",
    )
    with patch.object(ns.os, "open", side_effect=OSError(2, "nope")):
        argv = holder.run_argv(["true"])
    assert "--mount" in argv


def test_special_mounts_max_isolation_proc_hidepid():
    """The fresh procfs under max isolation must be hardened with hidepid=2."""
    from chroot_distro.commands.login.bindings import get_special_mounts

    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch("chroot_distro.commands.login.bindings._fs_supported", return_value=True),
    ):
        specials = get_special_mounts("/fake/rootfs", isolated=True, max_isolation=True)
    proc = [s for s in specials if s.fstype == "proc"][0]
    assert "hidepid=2" in proc.options


def test_max_isolation_dev_nodes_table():
    """The minimal device-node table must include the core character devices."""
    from chroot_distro.commands.login.bindings import MAX_ISOLATION_DEV_NODES

    names = {name for name, _maj, _min, _mode in MAX_ISOLATION_DEV_NODES}
    assert {"null", "zero", "tty", "random", "urandom", "full"} <= names
    # null is major 1, minor 3 by Linux convention.
    null = [n for n in MAX_ISOLATION_DEV_NODES if n[0] == "null"][0]
    assert null[1] == 1 and null[2] == 3


def test_resolve_rootfs_path_loop(tmp_path):
    import errno

    import pytest

    from chroot_distro.commands.login.passwd import resolve_rootfs_path

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    # Create a loop: /a -> /b -> /a
    os.symlink("/b", rootfs / "a")
    os.symlink("/a", rootfs / "b")

    with pytest.raises(OSError) as excinfo:
        resolve_rootfs_path(str(rootfs), "/a")
    assert excinfo.value.errno == errno.ELOOP


def test_translate_host_path_to_guest():
    from chroot_distro.commands.login import _translate_host_path_to_guest

    rootfs = "/var/lib/chroot-distro/ubuntu"

    # Test cases mapping (host_path, resolved_binds) -> expected_guest_path
    resolved_binds = [
        ("/dev", "/var/lib/chroot-distro/ubuntu/dev"),
        ("/sys", "/var/lib/chroot-distro/ubuntu/sys"),
        ("/home/sabamdarif", "/var/lib/chroot-distro/ubuntu/home/saba"),
        ("/home/sabamdarif/Documents/Github/chroot-distro", "/var/lib/chroot-distro/ubuntu/workspace"),
    ]

    # Exact match on longer/more specific bind mount
    assert _translate_host_path_to_guest(
        "/home/sabamdarif/Documents/Github/chroot-distro", rootfs, resolved_binds
    ) == "/workspace"

    # Subpath match under longer/more specific bind mount
    assert _translate_host_path_to_guest(
        "/home/sabamdarif/Documents/Github/chroot-distro/src", rootfs, resolved_binds
    ) == "/workspace/src"

    # Subpath match under less specific/home bind mount
    assert _translate_host_path_to_guest(
        "/home/sabamdarif/Downloads", rootfs, resolved_binds
    ) == "/home/saba/Downloads"

    # No match
    assert _translate_host_path_to_guest(
        "/var/log", rootfs, resolved_binds
    ) == "/var/log"

    # Exact match on home directory
    assert _translate_host_path_to_guest(
        "/home/sabamdarif", rootfs, resolved_binds
    ) == "/home/saba"


def test_resolve_override_flag_wins(monkeypatch):
    monkeypatch.setenv("CD_USER", "envuser")
    assert resolve_override("flaguser", "CD_USER") == "flaguser"


def test_resolve_override_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("CD_USER", "envuser")
    assert resolve_override(None, "CD_USER") == "envuser"


def test_resolve_override_none_when_unset(monkeypatch):
    monkeypatch.delenv("CD_USER", raising=False)
    assert resolve_override(None, "CD_USER") is None


def test_resolve_override_blank_env_is_none(monkeypatch):
    monkeypatch.setenv("CD_WORKDIR", "   ")
    assert resolve_override(None, "CD_WORKDIR") is None


def test_read_cd_env_splits_lines_and_filters(monkeypatch):
    monkeypatch.setenv("CD_ENV", "FOO=bar\nBAZ=qux\nnoequals\n  SPACED=1  ")
    assert read_cd_env() == ["FOO=bar", "BAZ=qux", "SPACED=1"]


def test_read_cd_env_empty_when_unset(monkeypatch):
    monkeypatch.delenv("CD_ENV", raising=False)
    assert read_cd_env() == []


def test_format_get_chroot_cmd_linux_is_copy_pasteable():
    import shlex

    from chroot_distro.commands.login import chroot_cmd

    env = {"PATH": "/usr/bin", "HOME": "/root", "TERM": "xterm"}
    argv = ["/usr/sbin/chroot", "--userspec=0:0", "/rootfs", "/bin/sh", "-c", "cd /root; exec bash -l"]
    with patch.object(chroot_cmd, "IS_TERMUX", False):
        out = chroot_cmd.format_get_chroot_cmd(env, argv)
    # real values, not redacted, and elevated
    assert "<redacted>" not in out
    assert out.startswith("sudo env")
    # backslash-newline continuations collapse back to the exact argv
    assert shlex.split(out.replace("\\\n", "")) == ["sudo", "env", "-i", *[f"{k}={v}" for k, v in env.items()], *argv]


def test_format_get_chroot_cmd_termux_su_wrapping():
    import shlex

    from chroot_distro.commands.login import chroot_cmd

    env = {"PATH": "/usr/bin"}
    argv = ["/usr/bin/chroot", "/rootfs", "/bin/sh", "-c", "cd '/my dir'; exec bash -l"]
    with (
        patch.object(chroot_cmd, "IS_TERMUX", True),
        patch.object(chroot_cmd.shutil, "which", return_value=None),
        patch("chroot_distro.elevate._find_termux_su", return_value="/system/bin/su"),
    ):
        out = chroot_cmd.format_get_chroot_cmd(env, argv)
    su, dash_c, body = shlex.split(out)
    assert [su, dash_c] == ["/system/bin/su", "-c"]
    # the -c string itself must round-trip to the original argv
    assert shlex.split(body.replace("\\\n", "")) == ["env", "-i", "PATH=/usr/bin", *argv]


def test_format_get_chroot_cmd_termux_prefers_sudo_package():
    from chroot_distro.commands.login import chroot_cmd

    with (
        patch.object(chroot_cmd, "IS_TERMUX", True),
        patch.object(chroot_cmd.shutil, "which", return_value="/data/data/com.termux/files/usr/bin/sudo"),
    ):
        out = chroot_cmd.format_get_chroot_cmd({"PATH": "/usr/bin"}, ["/usr/bin/chroot", "/rootfs"])
    assert out.startswith("sudo env")
