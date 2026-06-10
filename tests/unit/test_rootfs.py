import os
from unittest.mock import MagicMock, patch

from chroot_distro.helpers.rootfs import (
    host_nameservers,
    host_resolv_conf_path,
    register_android_ids,
    write_resolv_conf,
)


def test_host_resolv_conf_path_termux(tmp_path):
    prefix = tmp_path / "usr"
    etc = prefix / "etc"
    etc.mkdir(parents=True)
    (etc / "resolv.conf").write_text("nameserver 192.0.2.1\n")

    with (
        patch("chroot_distro.helpers.rootfs.IS_TERMUX", True),
        patch("chroot_distro.helpers.rootfs.TERMUX_PREFIX", str(prefix)),
    ):
        assert host_resolv_conf_path() == str(etc / "resolv.conf")
        assert host_nameservers() == ["192.0.2.1"]


def test_host_nameservers_skips_systemd_stub(tmp_path):
    run = tmp_path / "run" / "systemd" / "resolve"
    run.mkdir(parents=True)
    (run / "stub-resolv.conf").write_text("nameserver 127.0.0.53\n")
    (run / "resolv.conf").write_text("nameserver 192.0.2.2\nnameserver 192.0.2.3\n")
    resolv = tmp_path / "etc" / "resolv.conf"
    resolv.parent.mkdir(parents=True)
    os.symlink("../run/systemd/resolve/stub-resolv.conf", resolv)

    with (
        patch("chroot_distro.helpers.rootfs.host_resolv_conf_path", return_value=str(resolv)),
        patch("chroot_distro.helpers.rootfs._SYSTEMD_UPSTREAM_RESOLV", str(run / "resolv.conf")),
    ):
        assert host_nameservers() == ["192.0.2.2", "192.0.2.3"]


def test_write_resolv_conf_uses_host_nameservers(tmp_path):
    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)
    (etc / "resolv.conf").symlink_to("/run/systemd/resolve/stub-resolv.conf")

    with patch("chroot_distro.helpers.rootfs.host_nameservers", return_value=["192.0.2.4", "192.0.2.5"]):
        write_resolv_conf(str(rootfs))

    content = (etc / "resolv.conf").read_text()
    assert content == "nameserver 192.0.2.4\nnameserver 192.0.2.5\n"
    assert not (etc / "resolv.conf").is_symlink()


def test_write_resolv_conf_falls_back_to_defaults(tmp_path):
    rootfs = tmp_path / "rootfs"
    etc = rootfs / "etc"
    etc.mkdir(parents=True)

    with patch("chroot_distro.helpers.rootfs.host_nameservers", return_value=[]):
        write_resolv_conf(str(rootfs))

    content = (etc / "resolv.conf").read_text()
    assert "nameserver 8.8.8.8" in content
    assert "nameserver 8.8.4.4" in content


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

    with (
        patch("os.getuid", return_value=10123),
        patch("os.getgid", return_value=10123),
        patch("pwd.getpwuid", return_value=mock_pw),
        patch("os.getgroups", return_value=[10123, 9999]),
        patch("grp.getgrgid", side_effect=mock_getgrgid),
        patch(
            "chroot_distro.helpers.rootfs.termux_home_owner_ids",
            return_value=(10123, 10123),
        ),
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

    with (
        patch("os.getuid", return_value=10123),
        patch("os.getgid", return_value=10123),
        patch("pwd.getpwuid", return_value=mock_pw),
        patch("os.getgroups", return_value=[10123]),
        patch("grp.getgrgid", return_value=mock_gr1),
        patch(
            "chroot_distro.helpers.rootfs.termux_home_owner_ids",
            return_value=(10123, 10123),
        ),
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
