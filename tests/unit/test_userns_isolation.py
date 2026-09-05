"""Tests for Tier A/B user-namespace isolation wiring (plan 02)."""

from __future__ import annotations

from unittest.mock import mock_open, patch

from chroot_distro.commands.login import bindings
from chroot_distro.helpers import isolation
from chroot_distro.helpers import isolation_warnings as iw
from chroot_distro.helpers import namespace as ns
from chroot_distro.syscalls import unshare
from chroot_distro.syscalls._constants import CLONE_NEWUSER

# ── uid/gid map tiers ────────────────────────────────────────────────────────


def test_resolve_userns_map_identity_for_tier_a():
    assert ns.resolve_userns_map(ns.ISOLATION_TIER_USERNS) == ("0 0 65536\n", "0 0 65536\n")


def test_resolve_userns_map_subordinate_for_tier_b():
    assert ns.resolve_userns_map(ns.ISOLATION_TIER_REMAP) == ("0 100000 65536\n", "0 100000 65536\n")


def test_subid_base_env_override(monkeypatch):
    monkeypatch.setenv("CD_SUBID_BASE", "200000")
    assert ns.resolve_userns_map(ns.ISOLATION_TIER_REMAP) == ("0 200000 65536\n", "0 200000 65536\n")


def test_subid_base_ignores_bad_value(monkeypatch):
    monkeypatch.setenv("CD_SUBID_BASE", "not-a-number")
    assert ns.resolve_userns_map(ns.ISOLATION_TIER_REMAP) == ("0 100000 65536\n", "0 100000 65536\n")


# ── setgroups handling in _write_id_mappings ─────────────────────────────────


def test_write_id_mappings_root_does_not_deny_setgroups():
    m = mock_open()
    with patch("chroot_distro.syscalls.unshare.os.getuid", return_value=0), patch("builtins.open", m):
        unshare._write_id_mappings(123, ("0 0 65536\n", "0 0 65536\n"))
    written = [c.args[0] for c in m.call_args_list]
    assert "/proc/123/setgroups" not in written  # root keeps setgroups=allow
    assert "/proc/123/uid_map" in written
    assert "/proc/123/gid_map" in written


def test_write_id_mappings_unprivileged_denies_setgroups():
    m = mock_open()
    with patch("chroot_distro.syscalls.unshare.os.getuid", return_value=1000), patch("builtins.open", m):
        unshare._write_id_mappings(123, ("0 1000 1\n", "0 1000 1\n"))
    written = [c.args[0] for c in m.call_args_list]
    assert "/proc/123/setgroups" in written  # unprivileged must deny


# ── sysfs handling under a user namespace ────────────────────────────────────


def test_special_mounts_skip_fresh_sysfs_under_userns():
    specials = bindings.get_special_mounts("/tmp/rootfs", max_isolation=True, use_userns=True)
    assert not any(sm.fstype == "sysfs" for sm in specials)


def test_special_mounts_keep_fresh_sysfs_without_userns():
    specials = bindings.get_special_mounts("/tmp/rootfs", max_isolation=True, use_userns=False)
    assert any(sm.fstype == "sysfs" for sm in specials)


def test_max_isolation_binds_sys_recursively_under_userns():
    binds, rslave = bindings.get_bindings(rootfs="/tmp/rootfs", max_isolation=True, use_userns=True)
    assert [src for src, _ in binds] == ["/sys"]
    assert rslave  # /sys guest path is marked rslave


def test_max_isolation_binds_nothing_without_userns():
    binds, rslave = bindings.get_bindings(rootfs="/tmp/rootfs", max_isolation=True, use_userns=False)
    assert binds == []
    assert rslave == []


def test_bind_is_recursive_sys_and_dev_under_userns():
    assert isolation.bind_is_recursive("/sys", "/r/sys", "/r/run", use_userns=True)
    assert isolation.bind_is_recursive("/dev", "/r/dev", "/r/run", use_userns=True)
    # Without a userns, /sys is a plain (non-recursive) bind.
    assert not isolation.bind_is_recursive("/sys", "/r/sys", "/r/run", use_userns=False)


# ── warnings / tier reporting ────────────────────────────────────────────────


def test_emit_warnings_replaces_userns_line_when_mounts_rejected(capsys):
    # CLONE_NEWUSER missing because in-userns mounts were rejected: the generic
    # "not available" line is suppressed in favour of the specific note.
    iw.emit_isolation_warnings(0, CLONE_NEWUSER, 0, userns_mounts_ok=False)
    err = capsys.readouterr().err
    assert "rejects" in err
    assert "User namespace (CLONE_NEWUSER) not available" not in err
