from chroot_distro.commands.restore import _dest_path
from chroot_distro.helpers.tar_stream import detect_compression


# ── _detect_compression ───────────────────────────────────────────────────────
def test_detect_compression_gzip():
    assert detect_compression(b"\x1f\x8b\x08rest") == "gz"


def test_detect_compression_bzip2():
    assert detect_compression(b"BZh91AY&SY") == "bz2"
    assert detect_compression(b"BZh9\x17rE8P\x90") == "bz2"


def test_detect_compression_xz():
    assert detect_compression(b"\xfd7zXZ\x00rest") == "xz"


def test_detect_compression_zstd():
    assert detect_compression(b"\x28\xb5\x2f\xfdrest") == "zst"


def test_detect_compression_unknown_is_empty():
    assert detect_compression(b"plain tar data") == ""


# ── _dest_path: rejection cases ────────────────────────────────────────────────
def test_dest_path_empty_or_dot():
    assert _dest_path("") is None
    assert _dest_path(".") is None


def test_dest_path_traversal_rejected():
    assert _dest_path("mybox/../etc/passwd") is None


def test_dest_path_bare_file_rejected():
    # single component, not a dir member -> nothing to map
    assert _dest_path("loosefile") is None


def test_dest_path_invalid_container_name_rejected():
    assert _dest_path("bad name/rootfs/x") is None


# ── _dest_path: backup layout ──────────────────────────────────────────────────
def test_dest_path_new_manifest():
    assert _dest_path("mybox/manifest.json") == ("mybox", None)


def test_dest_path_new_rootfs_file():
    assert _dest_path("mybox/rootfs/etc/hostname") == ("mybox", ("etc", "hostname"))


def test_dest_path_trailing_slash_rejected():
    # trailing slash -> empty final part -> rejected by the traversal guard
    assert _dest_path("mybox/rootfs/") is None
    assert _dest_path("mybox/") is None
