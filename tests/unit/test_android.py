from unittest.mock import patch

from chroot_distro.helpers.android import configure_android_rootfs


def test_configure_android_rootfs_apt_gid(tmp_path):
    # Setup rootfs path structure
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)

    passwd_path = etc_dir / "passwd"
    passwd_path.write_text("_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n")

    group_path = etc_dir / "group"
    group_path.write_text("nogroup:x:65534:\n")

    # Mock IS_TERMUX to True to execute configure_android_rootfs logic
    with patch("chroot_distro.helpers.android.IS_TERMUX", True):
        configure_android_rootfs(str(tmp_path))

    # 1. Verify that etc/passwd was updated to set _apt primary GID to 3003 (aid_inet)
    passwd_content = passwd_path.read_text()
    assert "_apt:x:42:3003::/nonexistent:/usr/sbin/nologin" in passwd_content

    # 2. Verify that etc/group contains aid_inet (3003) and aid_net_raw (3004)
    # and that _apt is in their user lists
    group_content = group_path.read_text()
    assert "aid_inet:x:3003:root,_apt" in group_content
    assert "aid_net_raw:x:3004:root,_apt" in group_content


def test_configure_android_rootfs_no_apt(tmp_path):
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)

    passwd_path = etc_dir / "passwd"
    passwd_path.write_text("root:x:0:0:root:/root:/bin/bash\n")

    group_path = etc_dir / "group"
    group_path.write_text("root:x:0:\n")

    with patch("chroot_distro.helpers.android.IS_TERMUX", True):
        configure_android_rootfs(str(tmp_path))

    # Verify passwd and group are unchanged for _apt since it does not exist
    passwd_content = passwd_path.read_text()
    assert "root:x:0:0:root:/root:/bin/bash" in passwd_content
    assert "_apt" not in passwd_content

    group_content = group_path.read_text()
    assert "aid_inet:x:3003:root" in group_content
    assert "aid_net_raw:x:3004:root" in group_content
    assert "_apt" not in group_content
