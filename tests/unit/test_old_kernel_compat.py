"""Old-kernel fault injection: mount phases must degrade, not abort.

Errnos seen on real vendor kernels: file bind -> EINVAL (3.4.112),
devpts stack -> EBUSY (4.4, covered in test_devpts_single_instance),
tmpfs option rejects (toybox/SELinux).
"""

import errno
from unittest.mock import patch

import pytest

from chroot_distro.commands.login import bindings
from chroot_distro.commands.login.bindings import SpecialMount
from chroot_distro.exceptions import MountError
from chroot_distro.helpers import isolation, mount_manager


# ── apply_bind_mounts failure policy ───────────────────────────────────────────
def _run_binds(monkeypatch, tmp_path, binds, best_effort, failing_src):
    mounted = []

    def fake_safe_mount(src, dst, **kwargs):
        if src == failing_src:
            raise MountError(f"Failed to mount {src} to {dst}: [Errno 22] mount(2): Invalid argument (EINVAL)")
        mounted.append(src)

    monkeypatch.setattr(isolation.mount_manager, "safe_mount", fake_safe_mount)
    isolation.apply_bind_mounts(str(tmp_path), binds, best_effort_sources=best_effort)
    return mounted


def test_best_effort_bind_failure_is_skipped(monkeypatch, tmp_path):
    binds = [
        ("/dev", str(tmp_path / "dev")),
        ("/property_contexts", str(tmp_path / "property_contexts")),
        ("/data", str(tmp_path / "data")),
    ]
    mounted = _run_binds(
        monkeypatch, tmp_path, binds, frozenset({"/property_contexts"}), failing_src="/property_contexts"
    )
    # The failure is skipped and the remaining binds still happen.
    assert mounted == ["/dev", "/data"]


def test_required_bind_failure_raises(monkeypatch, tmp_path):
    binds = [("/dev", str(tmp_path / "dev")), ("/data", str(tmp_path / "data"))]
    with pytest.raises(MountError):
        _run_binds(monkeypatch, tmp_path, binds, frozenset({"/property_contexts"}), failing_src="/dev")


# ── best_effort_bind_sources classification ────────────────────────────────────
def test_best_effort_sources_cover_android_extras_only():
    with (
        patch.object(bindings, "system_bindings", return_value=[("/property_contexts", "/property_contexts")]),
        patch.object(bindings, "dalvik_cache_bindings", return_value=[("/data/dalvik-cache", "/data/dalvik-cache")]),
        patch.object(bindings, "storage_bindings", return_value=[("/storage", "/storage")]),
        patch.object(bindings, "termux_app_bindings", return_value=[]),
    ):
        srcs = bindings.best_effort_bind_sources()
    assert srcs == {"/property_contexts", "/data/dalvik-cache", "/storage"}
    assert "/dev" not in srcs


def test_best_effort_sources_empty_off_termux():
    # All four generators gate on IS_TERMUX.
    with patch.object(bindings, "IS_TERMUX", False):
        assert bindings.best_effort_bind_sources() == frozenset()


# ── tmpfs option rejects fall back to reduced options ──────────────────────────
def test_tmpfs_size_reject_falls_back(tmp_path, monkeypatch):
    (tmp_path / "dev" / "shm").mkdir(parents=True)
    attempts = []

    def fake_mount_filesystem(source, target, fstype, options=""):
        attempts.append(options)
        if "size=" in options:
            raise OSError(errno.EINVAL, "mount(2): Invalid argument (EINVAL)")

    monkeypatch.setattr(mount_manager, "is_mounted", lambda target, holder=None: False)
    monkeypatch.setattr(mount_manager, "mount_filesystem", fake_mount_filesystem)

    sm = SpecialMount(
        fstype="tmpfs", source="tmpfs", target="/dev/shm", options="size=256M,mode=1777", optional=True
    )
    assert mount_manager.apply_special_mount(str(tmp_path), sm) is True
    assert attempts == ["size=256M,mode=1777", "mode=1777"]
