from unittest.mock import patch

from chroot_distro.syscalls import mount
from chroot_distro.syscalls._constants import (
    MS_BIND,
    MS_NODEV,
    MS_NOSUID,
    MS_PRIVATE,
    MS_RDONLY,
    MS_REC,
    MS_REMOUNT,
)


# ── _encode ─────────────────────────────────────────────────────────────────
def test_encode_none_passthrough():
    assert mount._encode(None) is None
    assert mount._encode("abc") == b"abc"


# ── _parse_mount_options ──────────────────────────────────────────────────────
def test_parse_mount_options_empty():
    assert mount._parse_mount_options("") == 0


def test_parse_mount_options_recognised():
    flags = mount._parse_mount_options("ro,nosuid,nodev")
    assert flags == (MS_RDONLY | MS_NOSUID | MS_NODEV)


def test_parse_mount_options_ignores_unknown():
    # size=64m belongs in data, not flags -> ignored here.
    assert mount._parse_mount_options("ro,size=64m") == MS_RDONLY


# ── _parse_and_split_mount_options ────────────────────────────────────────────
def test_parse_and_split_separates_data():
    flags, data = mount._parse_and_split_mount_options("ro,mode=0755,nosuid")
    assert flags == (MS_RDONLY | MS_NOSUID)
    assert data == "mode=0755"


def test_parse_and_split_empty():
    assert mount._parse_and_split_mount_options("", initial_flags=MS_REC) == (MS_REC, "")


# ── native_mount ──────────────────────────────────────────────────────────────
def test_native_mount_encodes_and_forwards():
    with patch.object(mount, "libc_mount") as m:
        mount.native_mount("src", "/tgt", "tmpfs", 5, "mode=0755")
    m.assert_called_once_with(b"src", b"/tgt", b"tmpfs", 5, b"mode=0755")


def test_native_mount_none_args():
    with patch.object(mount, "libc_mount") as m:
        mount.native_mount(None, "/tgt", None, 0, None)
    m.assert_called_once_with(None, b"/tgt", None, 0, None)


# ── bind_mount ────────────────────────────────────────────────────────────────
def test_bind_mount_plain():
    with patch.object(mount, "libc_mount") as m:
        mount.bind_mount("/src", "/tgt")
    # Only the initial bind, no remount (no extra flags).
    m.assert_called_once()
    assert m.call_args.args[3] == MS_BIND


def test_bind_mount_recursive_readonly_remounts():
    with patch.object(mount, "libc_mount") as m:
        mount.bind_mount("/src", "/tgt", recursive=True, readonly=True)
    assert m.call_count == 2
    first, second = m.call_args_list
    assert first.args[3] == (MS_BIND | MS_REC)
    assert second.args[3] == (MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC)


def test_bind_mount_options_trigger_remount():
    with patch.object(mount, "libc_mount") as m:
        mount.bind_mount("/src", "/tgt", options="nosuid")
    assert m.call_count == 2
    assert m.call_args_list[1].args[3] == (MS_REMOUNT | MS_BIND | MS_NOSUID)


# ── mount_filesystem ──────────────────────────────────────────────────────────
def test_mount_filesystem_splits_options():
    with patch.object(mount, "libc_mount") as m:
        mount.mount_filesystem("tmpfs", "/tgt", "tmpfs", options="nosuid,size=64m")
    args = m.call_args.args
    assert args[2] == b"tmpfs"
    assert args[3] == MS_NOSUID
    assert args[4] == b"size=64m"


# ── set_propagation ───────────────────────────────────────────────────────────
def test_set_propagation():
    with patch.object(mount, "libc_mount") as m:
        mount.set_propagation("/", MS_PRIVATE | MS_REC)
    args = m.call_args.args
    assert args[0] == b"none"
    assert args[1] == b"/"
    assert args[3] == (MS_PRIVATE | MS_REC)
