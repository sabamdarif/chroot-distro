import gzip
import os
import sys
import zlib

if sys.version_info >= (3, 14):
    import tarfile

    from compression import zstd
else:
    from backports import zstd
    from backports.zstd import tarfile

from chroot_distro.helpers.layer_diff import (
    _file_crc32,
    _whiteout_paths,
    diff_snapshots,
    snapshot,
    write_files_layer,
    write_layer_tar,
)


def test_file_crc32_and_nonexistent(tmp_path):
    (tmp_path / "test.txt").write_text("hello world")
    dir_fd = os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        # Non-existent file should return 0xFFFFFFFF
        assert _file_crc32(dir_fd, "does_not_exist") == 0xFFFFFFFF

        # Valid file should return correct CRC32
        expected = zlib.crc32(b"hello world") & 0xFFFFFFFF
        assert _file_crc32(dir_fd, "test.txt") == expected
    finally:
        os.close(dir_fd)


def test_snapshot_basic(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    # Create a directory, a file, and a symlink
    sub = rootfs / "usr"
    sub.mkdir()

    f = rootfs / "usr" / "file.txt"
    f.write_text("hello")

    link = rootfs / "link"
    link.symlink_to("usr/file.txt")

    snap = snapshot(str(rootfs))

    assert "usr" in snap
    assert snap["usr"][0] == "dir"

    assert "usr/file.txt" in snap
    assert snap["usr/file.txt"][0] == "file"
    assert snap["usr/file.txt"][1] == 5  # size

    assert "link" in snap
    assert snap["link"] == ("symlink", "usr/file.txt")


def test_diff_snapshots():
    before = {
        "dir": ("dir", 0o755),
        "file1": ("file", 10, 1000, 0o644, 12345),
        "file2": ("file", 20, 1000, 0o644, 67890),
    }

    # file1 modified (different size/CRC32), file2 deleted, file3 added
    after = {
        "dir": ("dir", 0o755),
        "file1": ("file", 15, 1001, 0o644, 54321),
        "file3": ("file", 5, 1002, 0o644, 11111),
    }

    added, modified, deleted = diff_snapshots(before, after)

    assert added == ["file3"]
    assert modified == ["file1"]
    assert deleted == ["file2"]


def test_whiteout_paths():
    deleted = ["usr/bin/git", "etc/hosts"]
    surviving_dirs = ["usr/bin", "etc"]

    wh = _whiteout_paths(deleted, surviving_dirs)

    # Whiteouts for deleted files: .wh.<basename> inside parent dir
    # Opaque directory indicator: .wh..wh..opq inside directories
    expected = [
        "etc/.wh.hosts",
        "usr/bin/.wh.git",
        "etc/.wh..wh..opq",
        "usr/bin/.wh..wh..opq",
    ]
    assert sorted(wh) == sorted(expected)


def test_write_layer_tar(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    f1 = rootfs / "hello.txt"
    f1.write_text("hello layer")

    # 1. Gzip compressed layer
    out_tar = tmp_path / "layer.tar.gz"

    digest, _size, diff_id = write_layer_tar(
        rootfs=str(rootfs),
        paths_to_pack=["hello.txt"],
        deleted=["deleted.txt"],
        out_path=str(out_tar),
        opaque_dirs=["empty_dir"],
    )

    # Returned hashes must be sha256
    assert digest.startswith("sha256:")
    assert diff_id.startswith("sha256:")
    assert out_tar.exists()

    # Unpack tar to verify contents
    with gzip.open(out_tar, "rb") as gz, tarfile.open(fileobj=gz, mode="r:") as tf:
        members = tf.getnames()
        assert "hello.txt" in members
        assert ".wh.deleted.txt" in members
        assert "empty_dir/.wh..wh..opq" in members

        # Check content
        member = tf.extractfile("hello.txt")
        assert member.read() == b"hello layer"

    # 2. Zstandard compressed layer
    out_tar_zst = tmp_path / "layer.tar.zst"

    digest_zst, _size_zst, diff_id_zst = write_layer_tar(
        rootfs=str(rootfs),
        paths_to_pack=["hello.txt"],
        deleted=["deleted.txt"],
        out_path=str(out_tar_zst),
        opaque_dirs=["empty_dir"],
    )

    assert digest_zst.startswith("sha256:")
    assert diff_id_zst.startswith("sha256:")
    assert out_tar_zst.exists()

    # Unpack zstd tar to verify contents
    with zstd.ZstdFile(out_tar_zst, "rb") as zs, tarfile.open(fileobj=zs, mode="r:") as tf:
        members = tf.getnames()
        assert "hello.txt" in members
        assert ".wh.deleted.txt" in members
        assert "empty_dir/.wh..wh..opq" in members

        # Check content
        member = tf.extractfile("hello.txt")
        assert member.read() == b"hello layer"


def test_write_files_layer(tmp_path):
    out_tar = tmp_path / "layer.tar.gz"

    # Create some files on-disk to source
    src_file = tmp_path / "source.txt"
    src_file.write_text("sourced content")
    conf_file = tmp_path / "config.json"
    conf_file.write_bytes(b'{"port": 80}')

    file_map = {
        "etc/config.json": {"kind": "file", "src": str(conf_file), "mode": 0o600},
        "usr/bin/sourced": {"kind": "file", "src": str(src_file), "mode": 0o755},
        "usr/bin/link": {"kind": "symlink", "target": "sourced"},
        "var/log": {"kind": "dir", "mode": 0o700},
    }

    digest, _size, diff_id = write_files_layer(file_map, str(out_tar))

    assert digest.startswith("sha256:")
    assert diff_id.startswith("sha256:")
    assert out_tar.exists()

    # Unpack and verify structure
    with gzip.open(out_tar, "rb") as gz, tarfile.open(fileobj=gz, mode="r:") as tf:
        members = tf.getnames()

        # Parent directories should be synthesised automatically
        assert "etc" in members
        assert "usr" in members
        assert "usr/bin" in members
        assert "var" in members

        assert "etc/config.json" in members
        assert "usr/bin/sourced" in members
        assert "usr/bin/link" in members
        assert "var/log" in members

        # Verify specific modes/contents
        info_config = tf.getmember("etc/config.json")
        assert info_config.mode == 0o600
        assert tf.extractfile(info_config).read() == b'{"port": 80}'

        info_sourced = tf.getmember("usr/bin/sourced")
        assert info_sourced.mode == 0o755
        assert tf.extractfile(info_sourced).read() == b"sourced content"

        info_link = tf.getmember("usr/bin/link")
        assert info_link.type == tarfile.SYMTYPE
        assert info_link.linkname == "sourced"

        info_log = tf.getmember("var/log")
        assert info_log.type == tarfile.DIRTYPE
        assert info_log.mode == 0o700
