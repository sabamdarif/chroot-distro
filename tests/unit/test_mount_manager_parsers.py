from chroot_distro.helpers import mount_manager as mm


# ── decode_mount_path ──────────────────────────────────────────────────────────
def test_decode_mount_path_space():
    assert mm.decode_mount_path("/mnt/with\\040space") == "/mnt/with space"


def test_decode_mount_path_tab_and_newline():
    # \011 tab, \012 newline
    assert mm.decode_mount_path("/a\\011b\\012c") == "/a\tb\nc"


def test_decode_mount_path_no_escapes():
    assert mm.decode_mount_path("/plain/path") == "/plain/path"


# ── _mounts_under_rootfs_from_lines ─────────────────────────────────────────────
def test_mounts_under_rootfs_filters_and_sorts(monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    lines = [
        "proc /proc proc rw 0 0",
        "tmpfs /root/rootfs/dev tmpfs rw 0 0",
        "tmpfs /root/rootfs/dev/shm tmpfs rw 0 0",
        "tmpfs /root/rootfs tmpfs rw 0 0",
        "tmpfs /other/place tmpfs rw 0 0",
        "malformed-line",
    ]
    result = mm._mounts_under_rootfs_from_lines(lines, "/root/rootfs")
    # Only mounts at or under rootfs, deepest first.
    assert result == [
        "/root/rootfs/dev/shm",
        "/root/rootfs/dev",
        "/root/rootfs",
    ]


def test_mounts_under_rootfs_none_match(monkeypatch):
    monkeypatch.setattr("os.path.realpath", lambda p: p)
    assert mm._mounts_under_rootfs_from_lines(["proc /proc proc rw 0 0"], "/root/rootfs") == []


# ── _filter_bind_options ────────────────────────────────────────────────────────
def test_filter_bind_options_drops_selinux():
    assert mm._filter_bind_options("ro,z,nosuid,Z") == "ro,nosuid"


def test_filter_bind_options_empty_tokens_skipped():
    assert mm._filter_bind_options("ro,,nosuid,") == "ro,nosuid"


def test_filter_bind_options_only_relabel_flags():
    assert mm._filter_bind_options("z,Z") == ""
