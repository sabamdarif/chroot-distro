import os
from unittest.mock import patch

from chroot_distro.helpers.x11 import (
    GUEST_XAUTHORITY_PATH,
    guest_can_read_auth,
    provision_guest_xauthority,
    resolve_host_x11_env,
    resolve_invoking_uid,
    x11_auth_bind_path,
)


def test_resolve_invoking_uid_sudo():
    with patch.dict(os.environ, {"SUDO_UID": "1000"}, clear=False):
        assert resolve_invoking_uid() == 1000


def test_resolve_invoking_uid_fallback():
    with patch.dict(os.environ, {}, clear=True), patch("os.getuid", return_value=1001):
        assert resolve_invoking_uid() == 1001


def test_resolve_host_x11_env_from_environ(tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    xauth = home / ".Xauthority"
    xauth.write_text("cookie")

    with (
        patch.dict(
            os.environ,
            {
                "DISPLAY": ":1",
                "XAUTHORITY": str(xauth),
                "XDG_RUNTIME_DIR": "/run/user/1000",
            },
            clear=True,
        ),
        patch("chroot_distro.helpers.x11.resolve_invoking_uid", return_value=1000),
        patch("chroot_distro.helpers.x11._invoking_home", return_value=str(home)),
    ):
        env, binds = resolve_host_x11_env()

    assert env["DISPLAY"] == ":1"
    assert env["XAUTHORITY"] == str(xauth)
    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert binds == [str(xauth)]


def test_resolve_host_x11_env_runtime_xauthority_no_extra_bind():
    xauth = "/run/user/1000/.mutter-Xwaylandauth.ABC"

    with (
        patch.dict(os.environ, {"DISPLAY": ":1", "XAUTHORITY": xauth}, clear=True),
        patch("chroot_distro.helpers.x11.resolve_invoking_uid", return_value=1000),
        patch("chroot_distro.helpers.x11._invoking_home", return_value="/home/alice"),
        patch("os.path.isfile", return_value=True),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000"),
    ):
        env, binds = resolve_host_x11_env()

    assert env["XAUTHORITY"] == xauth
    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert binds == []


def test_resolve_host_x11_env_sudo_fallback(tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    xauth = home / ".Xauthority"
    xauth.write_text("cookie")
    runtime = tmp_path / "run" / "user" / "1000"
    runtime.mkdir(parents=True)

    with (
        patch.dict(os.environ, {"SUDO_UID": "1000"}, clear=True),
        patch("chroot_distro.helpers.x11.get_invoking_env", return_value={}),
        patch("chroot_distro.helpers.x11.resolve_invoking_uid", return_value=1000),
        patch("chroot_distro.helpers.x11._invoking_home", return_value=str(home)),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000" or str(p).endswith("1000")),
        patch("os.path.isfile", side_effect=lambda p: str(p).endswith(".Xauthority")),
    ):
        env, _binds = resolve_host_x11_env()

    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert env["XAUTHORITY"] == os.path.join(str(home), ".Xauthority")


def test_x11_auth_bind_path_rejects_unsafe(tmp_path):
    unsafe = tmp_path / "etc" / "shadow"
    unsafe.parent.mkdir(parents=True)
    unsafe.write_text("nope")

    with (
        patch("chroot_distro.helpers.x11.resolve_invoking_uid", return_value=1000),
        patch("chroot_distro.helpers.x11._invoking_home", return_value=str(tmp_path / "home")),
    ):
        assert x11_auth_bind_path(str(unsafe)) is None


def test_guest_can_read_auth_owner():
    with patch("os.stat") as mock_stat:
        mock_stat.return_value.st_uid = 1000
        mock_stat.return_value.st_mode = 0o600
        assert guest_can_read_auth(1000, "/home/user/.Xauthority") is True


def test_guest_can_read_auth_world_readable():
    with patch("os.stat") as mock_stat:
        mock_stat.return_value.st_uid = 0
        mock_stat.return_value.st_mode = 0o604
        assert guest_can_read_auth(1000, "/tmp/.Xauthority") is True


def test_guest_can_read_auth_denied():
    with patch("os.stat") as mock_stat:
        mock_stat.return_value.st_uid = 1000
        mock_stat.return_value.st_mode = 0o600
        assert guest_can_read_auth(1001, "/home/user/.Xauthority") is False


def test_get_bindings_x11_auth_binds():
    from chroot_distro.commands.login.bindings import get_bindings

    xauth = "/home/alice/.Xauthority"
    with patch("os.path.exists", return_value=True), patch("chroot_distro.commands.login.bindings.IS_TERMUX", False):
        binds, _ = get_bindings(
            rootfs="/fake/rootfs",
            shared_display=True,
            display_auth_binds=[xauth],
        )
    srcs = {src for src, _ in binds}
    assert xauth in srcs
    assert "/tmp/.X11-unix" in srcs


def test_provision_guest_xauthority(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    host_xauth = tmp_path / "host.xauth"
    host_xauth.write_bytes(b"\x00")

    guest_file = rootfs / "var" / "tmp" / ".chroot-distro-xauthority"

    def fake_run(cmd, capture_output, check):
        if cmd[:4] == ["xauth", "-f", str(host_xauth), "extract"]:
            guest_file.parent.mkdir(parents=True, exist_ok=True)
            guest_file.write_bytes(b"guest-cookie")
            return type("R", (), {"returncode": 0})()
        return type("R", (), {"returncode": 1})()

    with (
        patch("shutil.which", return_value="/usr/bin/xauth"),
        patch("subprocess.run", side_effect=fake_run),
        patch("os.chown"),
        patch("os.path.isfile", return_value=True),
    ):
        result = provision_guest_xauthority(
            str(rootfs),
            host_xauthority=str(host_xauth),
            display=":1",
            guest_uid=1001,
            guest_gid=1001,
        )

    assert result == GUEST_XAUTHORITY_PATH
    assert guest_file.is_file()
    assert oct(guest_file.stat().st_mode & 0o777) == "0o600"


def test_discover_runtime_xauthority(tmp_path):
    from chroot_distro.helpers.x11 import _discover_runtime_xauthority

    runtime = tmp_path / "run" / "user" / "1000"
    runtime.mkdir(parents=True)
    older = runtime / ".mutter-Xwaylandauth.old"
    newer = runtime / ".mutter-Xwaylandauth.new"
    older.write_text("a")
    newer.write_text("b")

    with (
        patch("chroot_distro.helpers.x11.os.path.isdir", return_value=True),
        patch(
            "chroot_distro.helpers.x11.glob.glob",
            side_effect=lambda pattern: [str(older), str(newer)] if "mutter-Xwaylandauth" in pattern else [],
        ),
        patch("chroot_distro.helpers.x11.os.path.isfile", return_value=True),
        patch(
            "chroot_distro.helpers.x11.os.path.getmtime",
            side_effect=lambda p: 1.0 if str(p).endswith("old") else 2.0,
        ),
    ):
        assert _discover_runtime_xauthority(1000) == str(newer)


def test_provision_guest_xauthority_no_xauth(tmp_path):
    with patch("shutil.which", return_value=None):
        assert (
            provision_guest_xauthority(
                str(tmp_path),
                host_xauthority="/home/user/.Xauthority",
                display=":1",
                guest_uid=1001,
                guest_gid=1001,
            )
            is None
        )


def test_get_host_env_var():
    from chroot_distro.helpers.x11 import get_host_env_var

    # 1. Variable is in os.environ
    with patch.dict(os.environ, {"TEST_VAR": "env_val"}, clear=True):
        assert get_host_env_var("TEST_VAR", "fallback") == "env_val"

    # 2. Variable is in invoking_env
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("chroot_distro.helpers.x11.get_invoking_env", return_value={"TEST_VAR": "invoking_val"}),
    ):
        assert get_host_env_var("TEST_VAR", "fallback") == "invoking_val"

    # 3. Variable is in neither, returns fallback
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("chroot_distro.helpers.x11.get_invoking_env", return_value={}),
    ):
        assert get_host_env_var("TEST_VAR", "fallback") == "fallback"

