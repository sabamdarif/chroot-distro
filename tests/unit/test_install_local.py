from unittest.mock import MagicMock

import io
import json
import os
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

import pytest

from chroot_distro.commands import install_local


def test_oci_read_json_rejects_non_regular_file():
    tf = MagicMock()
    member = MagicMock()
    member.isreg.return_value = False
    member_map = {"index.json": member}

    with pytest.raises(RuntimeError, match="not a regular file"):
        install_local._oci_read_json(tf, member_map, "index.json")


def test_oci_cache_layer_rejects_non_regular_file():
    tf = MagicMock()
    member = MagicMock()
    member.isreg.return_value = False
    digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    blob_path = "blobs/sha256/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    member_map = {blob_path: member}

    with pytest.raises(RuntimeError, match="not a regular file"):
        install_local._oci_cache_layer(tf, member_map, digest)


def _write_backup_archive(path, name, manifest_bytes, non_regular_manifest=False):
    """Write a backup-shaped tar: <name>/manifest.json + <name>/rootfs/..."""
    with tarfile.open(path, "w") as tf:
        if non_regular_manifest:
            link = tarfile.TarInfo(f"{name}/manifest.json")
            link.type = tarfile.SYMTYPE
            link.linkname = "rootfs/etc/passwd"
            tf.addfile(link)
        else:
            info = tarfile.TarInfo(f"{name}/manifest.json")
            info.size = len(manifest_bytes)
            tf.addfile(info, io.BytesIO(manifest_bytes))
        rootfs = tarfile.TarInfo(f"{name}/rootfs")
        rootfs.type = tarfile.DIRTYPE
        rootfs.mode = 0o755
        tf.addfile(rootfs)
        etc = tarfile.TarInfo(f"{name}/rootfs/etc")
        etc.type = tarfile.DIRTYPE
        etc.mode = 0o755
        tf.addfile(etc)
        f = tarfile.TarInfo(f"{name}/rootfs/etc/passwd")
        payload = b"root:x:0:0:root:/root:/bin/sh\n"
        f.size = len(payload)
        f.mode = 0o644
        tf.addfile(f, io.BytesIO(payload))


def test_detect_backup_manifest():
    names = [
        "oracle/manifest.json",
        "oracle/rootfs",
        "oracle/rootfs/etc/passwd",
    ]
    assert install_local._detect_backup_manifest(names) == "oracle/manifest.json"

    # A plain rootfs tarball (no wrapping dir, no sidecar manifest) is not a backup.
    assert install_local._detect_backup_manifest(["etc/passwd", "usr/bin/sh"]) is None

    # A manifest without a matching rootfs tree is not a backup.
    assert install_local._detect_backup_manifest(["oracle/manifest.json", "oracle/data"]) is None


def test_install_from_backup_returns_manifest_and_extracts_rootfs(tmp_path):
    manifest = {
        "image_ref": "example.com/oracle:1",
        "arch": "x86_64",
        "manifest": {"schemaVersion": 2},
        "image_config": {"config": {"User": "sqldev"}},
    }
    archive = tmp_path / "oracle.tar"
    _write_backup_archive(archive, "oracle", json.dumps(manifest).encode())

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    rootfs_fd = os.open(str(rootfs), os.O_RDONLY)
    try:
        result = install_local.install_from_local_file(str(archive), rootfs_fd, "x86_64")
    finally:
        os.close(rootfs_fd)

    assert result == manifest
    assert (rootfs / "etc" / "passwd").read_text().startswith("root:x:0:0")


def test_install_from_backup_ignores_non_regular_manifest(tmp_path):
    archive = tmp_path / "oracle.tar"
    _write_backup_archive(archive, "oracle", b"{}", non_regular_manifest=True)

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    rootfs_fd = os.open(str(rootfs), os.O_RDONLY)
    try:
        result = install_local.install_from_local_file(str(archive), rootfs_fd, "x86_64")
    finally:
        os.close(rootfs_fd)

    # A non-regular manifest member is refused, so no metadata is returned, but
    # the rootfs still installs.
    assert result is None
    assert (rootfs / "etc" / "passwd").exists()


def test_install_from_backup_named_after_rootfs_dir(tmp_path):
    # A backup uses a fixed strip of 2, so a container named after a rootfs dir
    # (where the voted strip would tie toward 0) still lands its tree correctly.
    manifest = {"image_ref": "usr:1", "arch": "x86_64", "manifest": {}, "image_config": {}}
    archive = tmp_path / "usr.tar"
    _write_backup_archive(archive, "usr", json.dumps(manifest).encode())

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    rootfs_fd = os.open(str(rootfs), os.O_RDONLY)
    try:
        result = install_local.install_from_local_file(str(archive), rootfs_fd, "x86_64")
    finally:
        os.close(rootfs_fd)

    assert result == manifest
    assert (rootfs / "etc" / "passwd").read_text().startswith("root:x:0:0")
    # The wrapper and the sidecar manifest must not leak into the rootfs.
    assert not (rootfs / "manifest.json").exists()
    assert not (rootfs / "rootfs").exists()
    assert not (rootfs / "usr").exists()

