"""Single-instance devpts (kernel < 4.7 without CONFIG_DEVPTS_MULTIPLE_INSTANCES):

mounting the 'newinstance' devpts over the host /dev/pts bind returns EBUSY
because the kernel refuses stacking the lone instance on itself. The bind
already provides that instance, so apply_special_mount must reuse it.
"""

import errno

import pytest

from chroot_distro.commands.login.bindings import SpecialMount
from chroot_distro.helpers import mount_manager as mm


def _devpts_special() -> SpecialMount:
    return SpecialMount(
        fstype="devpts",
        source="devpts",
        target="/dev/pts",
        options="gid=5,mode=620,ptmxmode=0666,newinstance",
        mkdir=True,
        check="",
        optional=False,
    )


@pytest.fixture
def rootfs(tmp_path):
    (tmp_path / "dev" / "pts").mkdir(parents=True)
    return str(tmp_path)


def test_devpts_ebusy_reuses_existing_instance(rootfs, monkeypatch):
    # Host /dev/pts bind is mounted at target but is not our newinstance
    # (no ptmxmode=666), so the mount is attempted and the kernel says EBUSY.
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: True)
    monkeypatch.setattr(mm, "_mount_fs_and_options", lambda target: ("devpts", "rw,mode=600"))

    def fail_ebusy(*args, **kwargs):
        raise OSError(errno.EBUSY, "mount(2): Device or resource busy (EBUSY)")

    monkeypatch.setattr(mm, "mount_filesystem", fail_ebusy)

    assert mm.apply_special_mount(rootfs, _devpts_special()) is True


def test_devpts_ebusy_without_devpts_at_target_still_raises(rootfs, monkeypatch):
    # EBUSY with something else at the target is a real failure, not the
    # single-instance case; it must not be masked.
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: False)
    monkeypatch.setattr(mm, "_mount_fs_and_options", lambda target: ("", ""))

    def fail_ebusy(*args, **kwargs):
        raise OSError(errno.EBUSY, "mount(2): Device or resource busy (EBUSY)")

    monkeypatch.setattr(mm, "mount_filesystem", fail_ebusy)

    with pytest.raises(RuntimeError, match="mounting devpts"):
        mm.apply_special_mount(rootfs, _devpts_special())
