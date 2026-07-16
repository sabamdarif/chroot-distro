from unittest.mock import patch

from chroot_distro.syscalls import umount
from chroot_distro.syscalls._constants import MNT_DETACH, MNT_FORCE


def test_native_umount_plain():
    with patch.object(umount, "libc_umount2") as m:
        umount.native_umount("/tgt")
    m.assert_called_once_with(b"/tgt", 0)


def test_native_umount_lazy():
    with patch.object(umount, "libc_umount2") as m:
        umount.native_umount("/tgt", lazy=True)
    m.assert_called_once_with(b"/tgt", MNT_DETACH)


def test_native_umount_force():
    with patch.object(umount, "libc_umount2") as m:
        umount.native_umount("/tgt", force=True)
    m.assert_called_once_with(b"/tgt", MNT_FORCE)


def test_native_umount_lazy_and_force():
    with patch.object(umount, "libc_umount2") as m:
        umount.native_umount("/tgt", lazy=True, force=True)
    m.assert_called_once_with(b"/tgt", MNT_DETACH | MNT_FORCE)
