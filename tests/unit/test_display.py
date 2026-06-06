from unittest.mock import patch
import os
from chroot_distro.helpers.display import resolve_display_env, _resolve_dbus_env

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_dbus_env_empty(mock_uid, mock_inv_env):
    with patch("os.path.exists", return_value=False):
        assert _resolve_dbus_env() == {}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_dbus_env_fallback(mock_uid, mock_inv_env):
    with patch("os.path.exists", side_effect=lambda p: p == "/run/user/1000/bus"):
        assert _resolve_dbus_env() == {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1001)
@patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-custom"}, clear=True)
def test_resolve_dbus_env_host(mock_uid, mock_inv_env):
    assert _resolve_dbus_env() == {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-custom"}

@patch("chroot_distro.helpers.display.resolve_host_x11_env", return_value=({"DISPLAY": ":0"}, ["/tmp/.X11-unix"]))
@patch("chroot_distro.helpers.display.resolve_wayland_env", return_value={"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland"})
@patch("chroot_distro.helpers.display.resolve_sound_env", return_value={"PULSE_SERVER": "unix:/run/user/1000/pulse/native"})
@patch("chroot_distro.helpers.display._resolve_dbus_env", return_value={"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"})
def test_resolve_display_env(mock_dbus, mock_sound, mock_wayland, mock_x11):
    env, bind_paths = resolve_display_env()
    assert env == {
        "DISPLAY": ":0",
        "WAYLAND_DISPLAY": "wayland-0",
        "XDG_SESSION_TYPE": "wayland",
        "PULSE_SERVER": "unix:/run/user/1000/pulse/native",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
    }
    assert bind_paths == ["/tmp/.X11-unix"]
