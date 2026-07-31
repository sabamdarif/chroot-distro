"""devpts handling that must never leak into the host /dev/pts.

Single-instance kernels (< 4.7 without CONFIG_DEVPTS_MULTIPLE_INSTANCES) share
one superblock, so mounting devpts reconfigures the host; the host instance
must be reused via bind instead. On multi-instance kernels the fresh devpts
must not propagate a copy back onto the host /dev/pts.
"""

import errno

import pytest

from chroot_distro.commands import kernel_config as kc
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


@pytest.fixture
def multi_instance(monkeypatch):
    monkeypatch.setattr(mm, "_devpts_single_instance", lambda: False)


def test_devpts_ebusy_reuses_existing_instance(rootfs, monkeypatch, multi_instance):
    # Host /dev/pts bind is mounted at target but is not our newinstance
    # (no ptmxmode=666), so the mount is attempted and the kernel says EBUSY.
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: True)
    monkeypatch.setattr(mm, "_mount_fs_and_options", lambda target: ("devpts", "rw,mode=600"))

    def fail_ebusy(*args, **kwargs):
        raise OSError(errno.EBUSY, "mount(2): Device or resource busy (EBUSY)")

    monkeypatch.setattr(mm, "mount_filesystem", fail_ebusy)

    assert mm.apply_special_mount(rootfs, _devpts_special()) is True


def test_devpts_ebusy_without_devpts_at_target_still_raises(rootfs, monkeypatch, multi_instance):
    # EBUSY with something else at the target is a real failure, not the
    # single-instance case; it must not be masked.
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: False)
    monkeypatch.setattr(mm, "_mount_fs_and_options", lambda target: ("", ""))

    def fail_ebusy(*args, **kwargs):
        raise OSError(errno.EBUSY, "mount(2): Device or resource busy (EBUSY)")

    monkeypatch.setattr(mm, "mount_filesystem", fail_ebusy)

    with pytest.raises(RuntimeError, match="mounting devpts"):
        mm.apply_special_mount(rootfs, _devpts_special())


def test_probe_einval_means_single_instance(monkeypatch):
    # Pre-CONFIG kernels reject 'newinstance' with EINVAL ("bogus options");
    # that rejection identifies the single global instance.
    monkeypatch.setattr(kc, "kernel_version_tuple", lambda: (4, 4))
    monkeypatch.setattr(kc.os, "getuid", lambda: 0)

    def fail_einval(*args, **kwargs):
        raise OSError(errno.EINVAL, "mount(2): Invalid argument (EINVAL)")

    import chroot_distro.syscalls.mount as syscalls_mount

    monkeypatch.setattr(syscalls_mount, "native_mount", fail_einval)
    assert kc.probe_devpts_multi_instance() == kc.PROBE_ABSENT


def test_single_instance_never_mounts_devpts(rootfs, monkeypatch):
    # With the host bind already at the target, reuse it without a single
    # mount(2) call (the call itself would rewrite the host superblock).
    monkeypatch.setattr(mm, "_devpts_single_instance", lambda: True)
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: True)

    def boom(*args, **kwargs):
        raise AssertionError("mount(2) must not be attempted on single-instance devpts")

    monkeypatch.setattr(mm, "mount_filesystem", boom)
    monkeypatch.setattr(mm, "bind_mount", boom)

    assert mm.apply_special_mount(rootfs, _devpts_special()) is True


def test_single_instance_binds_host_pts_when_unmounted(rootfs, monkeypatch):
    monkeypatch.setattr(mm, "_devpts_single_instance", lambda: True)
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: False)
    binds = []
    monkeypatch.setattr(mm, "bind_mount", lambda src, dst, **kw: binds.append((src, dst)))

    assert mm.apply_special_mount(rootfs, _devpts_special()) is True
    assert binds == [("/dev/pts", f"{rootfs}/dev/pts")]


def test_stacking_makes_target_private_first(rootfs, monkeypatch, multi_instance):
    # The bind under the fresh devpts is a peer of the host /dev/pts; the
    # stacked mount must not propagate a copy back onto the host.
    monkeypatch.setattr(mm, "is_mounted", lambda target, holder=None: True)
    monkeypatch.setattr(mm, "_mount_fs_and_options", lambda target: ("devpts", "rw,mode=600,ptmxmode=000"))
    calls = []
    monkeypatch.setattr(mm, "set_propagation", lambda target, flags: calls.append((target, flags)))
    monkeypatch.setattr(mm, "mount_filesystem", lambda *a, **kw: None)

    assert mm.apply_special_mount(rootfs, _devpts_special()) is True
    assert calls == [(f"{rootfs}/dev/pts", mm.MS_PRIVATE)]
