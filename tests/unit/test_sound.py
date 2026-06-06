from unittest.mock import patch
import os
from chroot_distro.helpers.sound import resolve_sound_env

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.sound.resolve_invoking_uid", return_value=1000)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_sound_env_empty(mock_uid, mock_inv_env):
    with patch("os.path.exists", return_value=False):
        assert resolve_sound_env() == {}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.sound.resolve_invoking_uid", return_value=1000)
@patch.dict(os.environ, {}, clear=True)
def test_resolve_sound_env_fallback(mock_uid, mock_inv_env):
    with patch("os.path.exists", side_effect=lambda p: p == "/run/user/1000/pulse/native"):
        assert resolve_sound_env() == {"PULSE_SERVER": "unix:/run/user/1000/pulse/native"}

@patch("chroot_distro.helpers.x11.get_invoking_env", return_value={})
@patch("chroot_distro.helpers.sound.resolve_invoking_uid", return_value=1001)
@patch.dict(os.environ, {"PULSE_SERVER": "unix:/some/other/path"}, clear=True)
def test_resolve_sound_env_host(mock_uid, mock_inv_env):
    assert resolve_sound_env() == {"PULSE_SERVER": "unix:/some/other/path"}
