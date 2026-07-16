import os

from chroot_distro.commands import restore
from chroot_distro.paths import container_manifest, container_rootfs


# ── _detect_compression ───────────────────────────────────────────────────────
def test_detect_compression_gzip():
    assert restore._detect_compression(b"\x1f\x8b\x08rest") == "gz"


def test_detect_compression_bzip2():
    assert restore._detect_compression(b"BZh91") == "bz2"


def test_detect_compression_xz():
    assert restore._detect_compression(b"\xfd7zXZ\x00rest") == "xz"


def test_detect_compression_zstd():
    assert restore._detect_compression(b"\x28\xb5\x2f\xfdrest") == "zst"


def test_detect_compression_unknown_is_empty():
    assert restore._detect_compression(b"plain tar data") == ""


# ── _dest_path: rejection cases ────────────────────────────────────────────────
def test_dest_path_empty_or_dot():
    assert restore._dest_path("") == restore._SKIP
    assert restore._dest_path(".") == restore._SKIP


def test_dest_path_traversal_rejected():
    assert restore._dest_path("mybox/../etc/passwd") == restore._SKIP


def test_dest_path_bare_file_rejected():
    # single component, not a dir member -> nothing to map
    assert restore._dest_path("loosefile") == restore._SKIP


def test_dest_path_invalid_container_name_rejected():
    assert restore._dest_path("bad name/rootfs/x") == restore._SKIP


# ── _dest_path: legacy format ──────────────────────────────────────────────────
def test_dest_path_legacy_prefix():
    name, dest = restore._dest_path("installed-rootfs/mybox/etc/hostname")
    assert name == "mybox"
    assert dest == os.path.join(container_rootfs("mybox"), "etc", "hostname")


def test_dest_path_legacy_trailing_slash_rejected():
    # trailing slash -> empty final part -> rejected by the traversal guard
    assert restore._dest_path("installed-rootfs/mybox/") == restore._SKIP


def test_dest_path_legacy_missing_name():
    assert restore._dest_path("installed-rootfs/") == restore._SKIP


# ── _dest_path: new format ─────────────────────────────────────────────────────
def test_dest_path_new_manifest():
    name, dest = restore._dest_path("mybox/manifest.json")
    assert name == "mybox"
    assert dest == container_manifest("mybox")


def test_dest_path_new_rootfs_file():
    name, dest = restore._dest_path("mybox/rootfs/etc/hostname")
    assert name == "mybox"
    assert dest == os.path.join(container_rootfs("mybox"), "etc", "hostname")


def test_dest_path_trailing_slash_rejected():
    # trailing slash -> empty final part -> rejected by the traversal guard
    assert restore._dest_path("mybox/rootfs/") == restore._SKIP
    assert restore._dest_path("mybox/") == restore._SKIP


def test_dest_path_old_backcompat_layout():
    # <name>/<other> (not rootfs, not manifest) maps under rootfs
    name, dest = restore._dest_path("mybox/data/file")
    assert name == "mybox"
    assert dest == os.path.join(container_rootfs("mybox"), "data", "file")


# ── _is_rootfs_dest ────────────────────────────────────────────────────────────
def test_is_rootfs_dest_true_for_rootfs_and_children():
    rootfs = container_rootfs("mybox")
    assert restore._is_rootfs_dest("mybox", rootfs) is True
    assert restore._is_rootfs_dest("mybox", os.path.join(rootfs, "etc")) is True


def test_is_rootfs_dest_false_for_manifest():
    assert restore._is_rootfs_dest("mybox", container_manifest("mybox")) is False
