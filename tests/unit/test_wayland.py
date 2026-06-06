from unittest.mock import patch
import os
from chroot_distro.helpers.wayland import resolve_wayland_env, _runtime_dir, _wayland_socket_exists

def test_runtime_dir():
    assert _runtime_dir(1000) == "/run/user/1000"
    assert _runtime_dir(0) == "/run/user/0"

def test_wayland_socket_exists(tmp_path):
    socket_name = "wayland-test-socket"
    assert not _wayland_socket_exists(str(tmp_path), socket_name)
    (tmp_path / socket_name).touch()
    assert _wayland_socket_exists(str(tmp_path), socket_name)

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.wayland.resolve_invoking_uid", return_value=1001)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_wayland_env_empty(mock_uid, mock_inv_env):
    # Empty host env, no wayland-0 socket -> empty dict
    with patch("chroot_distro.helpers.wayland._wayland_socket_exists", return_value=False):
        assert resolve_wayland_env() == {}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.wayland.resolve_invoking_uid", return_value=1001)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_wayland_env_fallback_active(mock_uid, mock_inv_env):
    # Empty host env, but wayland-0 socket exists -> WAYLAND_DISPLAY = wayland-0
    with patch("chroot_distro.helpers.wayland._wayland_socket_exists", return_value=True):
        assert resolve_wayland_env() == {"WAYLAND_DISPLAY": "wayland-0"}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.wayland.resolve_invoking_uid", return_value=1002)
@patch.dict(os.environ, {
    "WAYLAND_DISPLAY": "wayland-custom",
    "XDG_SESSION_TYPE": "wayland",
    "XDG_CURRENT_DESKTOP": "GNOME",
    "DESKTOP_SESSION": "gnome",
}, clear=True)
def test_resolve_wayland_env_from_host(mock_uid, mock_inv_env):
    # Values from host forwarded, wayland socket check bypassed/unused
    assert resolve_wayland_env() == {
        "WAYLAND_DISPLAY": "wayland-custom",
        "XDG_SESSION_TYPE": "wayland",
        "XDG_CURRENT_DESKTOP": "GNOME",
        "DESKTOP_SESSION": "gnome",
    }
