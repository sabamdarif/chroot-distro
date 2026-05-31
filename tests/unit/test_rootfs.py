import os
from unittest.mock import MagicMock, patch
import pytest

from chroot_distro.helpers.rootfs import register_android_ids


def test_register_android_ids_basic(tmp_path):
    # Setup basic file layout
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)

    passwd_path = etc_dir / "passwd"
    shadow_path = etc_dir / "shadow"
    group_path = etc_dir / "group"
    gshadow_path = etc_dir / "gshadow"

    passwd_path.touch()
    shadow_path.touch()
    group_path.touch()
    gshadow_path.touch()

    # Pre-populate group with some standard Unix groups
    group_path.write_text("root:x:0:\nbin:x:1:\n")

    # Mocks for user/group queries
    mock_pw = MagicMock()
    mock_pw.pw_name = "u0_a123"

    mock_gr1 = MagicMock()
    mock_gr1.gr_name = "u0_a123"

    mock_gr2 = MagicMock()
    mock_gr2.gr_name = "everybody"

    def mock_getgrgid(g):
        if g == 10123:
            return mock_gr1
        if g == 9999:
            return mock_gr2
        raise KeyError()

    with patch("os.getuid", return_value=10123), \
         patch("os.getgid", return_value=10123), \
         patch("pwd.getpwuid", return_value=mock_pw), \
         patch("os.getgroups", return_value=[10123, 9999]), \
         patch("grp.getgrgid", side_effect=mock_getgrgid), \
         patch(
             "chroot_distro.helpers.rootfs.termux_home_owner_ids",
             return_value=(10123, 10123),
         ):
        register_android_ids(str(tmp_path))

    # Assert user entries were added to passwd/shadow
    passwd_content = passwd_path.read_text()
    assert "aid_u0_a123:x:10123:10123:Termux:/:/sbin/nologin" in passwd_content

    shadow_content = shadow_path.read_text()
    assert "aid_u0_a123:*:18446:0:99999:7:::" in shadow_content

    # Assert GID entries and Android specific groups were added to group
    group_content = group_path.read_text()
    # Termux app primary GID (from TERMUX_HOME ownership, not hardcoded):
    assert "termux:x:10123:" in group_content
    assert "aid_u0_a123:x:10123:" not in group_content
    assert "aid_everybody:x:9999:root,aid_u0_a123" in group_content
    # Android specific groups:
    assert "aid_inet:x:3003:" in group_content
    assert "aid_net_raw:x:3004:" in group_content
    assert "aid_bluetooth:x:1002:" in group_content
    assert "aid_admin:x:3005:" in group_content

    # Assert gshadow entries for supplementary host groups (not termux primary gid)
    gshadow_content = gshadow_path.read_text()
    assert "aid_everybody:*::root,aid_u0_a123" in gshadow_content


def test_register_android_ids_idempotent(tmp_path):
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)

    group_path = etc_dir / "group"
    group_path.write_text("root:x:0:\naid_inet:x:3003:\n")

    mock_pw = MagicMock()
    mock_pw.pw_name = "u0_a123"

    mock_gr1 = MagicMock()
    mock_gr1.gr_name = "u0_a123"

    with patch("os.getuid", return_value=10123), \
         patch("os.getgid", return_value=10123), \
         patch("pwd.getpwuid", return_value=mock_pw), \
         patch("os.getgroups", return_value=[10123]), \
         patch("grp.getgrgid", return_value=mock_gr1), \
         patch(
             "chroot_distro.helpers.rootfs.termux_home_owner_ids",
             return_value=(10123, 10123),
         ):
        # Run first time
        register_android_ids(str(tmp_path))
        
        # Run second time to verify idempotency
        register_android_ids(str(tmp_path))

    group_content = group_path.read_text()
    assert group_content.count("termux:x:10123:") == 1
    # Check that aid_inet appears exactly once
    assert group_content.count("aid_inet:x:3003:") == 1
    # Check that user group and other Android groups are also present
    assert "aid_net_raw:x:3004:" in group_content
