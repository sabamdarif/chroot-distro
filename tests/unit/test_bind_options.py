"""Tests for --bind mount-option parsing and safe_mount remount handling."""

from unittest.mock import MagicMock, patch

from chroot_distro.commands.login.bindings import (
    parse_bind_options,
    strip_bind_options,
)
from chroot_distro.helpers import mount_manager as mm


def test_strip_bind_options_forms():
    assert strip_bind_options(None) == []
    assert strip_bind_options([]) == []
    # host only
    assert strip_bind_options(["/host"]) == ["/host"]
    # host:guest
    assert strip_bind_options(["/host:/guest"]) == ["/host:/guest"]
    # host:guest:ro -> options stripped
    assert strip_bind_options(["/host:/guest:ro"]) == ["/host:/guest"]
    # host:guest:ro,nosuid -> options stripped
    assert strip_bind_options(["/host:/guest:ro,nosuid"]) == ["/host:/guest"]


def test_parse_bind_options_only_when_present():
    # No options -> not in the map
    assert parse_bind_options(["/host:/guest"]) == {}
    assert parse_bind_options(["/host"]) == {}
    # Options present -> keyed by normalized guest dst
    assert parse_bind_options(["/host:/guest:ro"]) == {"/guest": "ro"}
    assert parse_bind_options(["/host:/guest/:ro,z"]) == {"/guest": "ro,z"}


def test_parse_bind_options_multiple():
    result = parse_bind_options(
        [
            "/a:/mnt/a:ro",
            "/b:/mnt/b",
            "/c:/mnt/c:rw,nosuid",
        ]
    )
    assert result == {"/mnt/a": "ro", "/mnt/c": "rw,nosuid"}


def test_filter_bind_options_drops_selinux_flags():
    assert mm._filter_bind_options("ro") == "ro"
    assert mm._filter_bind_options("ro,z") == "ro"
    assert mm._filter_bind_options("z") == ""
    assert mm._filter_bind_options("Z,ro,nosuid") == "ro,nosuid"
    assert mm._filter_bind_options("") == ""


def test_safe_mount_no_options_is_single_bind():
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder)
    holder.do_bind_mount.assert_called_once_with(
        "/host/src", "/tmp/rootfs/mnt", recursive=False, options=""
    )


def test_safe_mount_ro_issues_remount():
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, options="ro")
    holder.do_bind_mount.assert_called_once_with(
        "/host/src", "/tmp/rootfs/mnt", recursive=False, options="ro"
    )


def test_safe_mount_only_selinux_option_skips_remount():
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, options="z")
    holder.do_bind_mount.assert_called_once_with(
        "/host/src", "/tmp/rootfs/mnt", recursive=False, options=""
    )


def test_safe_mount_recursive_ro_uses_rbind_remount():
    holder = MagicMock()
    with (
        patch("os.path.isdir", return_value=True),
        patch("os.path.exists", return_value=True),
        patch("os.path.realpath", side_effect=lambda p: p),
        patch("os.makedirs"),
        patch.object(mm, "is_mounted", return_value=False),
    ):
        mm.safe_mount("/host/src", "/tmp/rootfs/mnt", holder=holder, recursive=True, options="ro")
    holder.do_bind_mount.assert_called_once_with(
        "/host/src", "/tmp/rootfs/mnt", recursive=True, options="ro"
    )
