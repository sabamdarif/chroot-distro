import hashlib
import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

import pytest

from chroot_distro import atomic
from chroot_distro.arch import Platform
from chroot_distro.commands import install_local
from chroot_distro.helpers import oci_writer
from chroot_distro.helpers.build_engine import PlatformResult
from chroot_distro.helpers.docker import cache


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
        install_local._oci_cache_layer(tf, member_map, install_local._Blob(digest, 0), "unused")


def _add_bytes(tf, name, data):
    entry = tarfile.TarInfo(name)
    entry.size = len(data)
    tf.addfile(entry, io.BytesIO(data))


def _descriptor(data):
    return {"digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}


def _blob_path(descriptor):
    return "blobs/" + descriptor["digest"].replace(":", "/")


def _layer_bytes(payload):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        _add_bytes(tf, "etc/fixture", payload)
    return out.getvalue()


@pytest.fixture
def oci(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    base_cache = runtime / "cache"
    monkeypatch.setattr(install_local, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(install_local, "BASE_CACHE_DIR", str(base_cache))
    monkeypatch.setattr(install_local, "IS_TERMUX", True)
    monkeypatch.setattr(cache, "LAYER_CACHE_DIR", str(base_cache / "oci_layers"))
    monkeypatch.setattr(atomic, "_STATE_ROOTS", (str(runtime),))
    archive = tmp_path / "image.oci.tar"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    return archive, rootfs, base_cache


def _write_oci(
    archive, layer, *, corrupt=None, member="regular", layer_descriptor=None, fallback=False, config=None
):
    if config is None:
        config = {"architecture": "amd64", "os": "linux", "config": None}
    config_bytes = json.dumps(config).encode()
    config_blob = _descriptor(config_bytes)
    layer_blob = _descriptor(layer) if layer_descriptor is None else layer_descriptor
    manifest_bytes = json.dumps({"config": config_blob, "layers": [layer_blob]}).encode()
    manifest_blob = _descriptor(manifest_bytes)
    entries = [manifest_blob]
    if fallback:
        entries.append({"digest": "unused", "size": 0})
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        _add_bytes(tf, "index.json", json.dumps({"manifests": entries}).encode())
        for name, blob, data in (
            ("manifest", manifest_blob, manifest_bytes),
            ("config", config_blob, config_bytes),
        ):
            _add_bytes(tf, _blob_path(blob), b"!" + data[1:] if corrupt == name else data)
        if member == "regular":
            _add_bytes(tf, _blob_path(layer_blob), b"!" + layer[1:] if corrupt == "layer" else layer)
        elif member == "symlink":
            entry = tarfile.TarInfo(_blob_path(layer_blob))
            entry.type = tarfile.SYMTYPE
            entry.linkname = "index.json"
            tf.addfile(entry)
    return layer_blob


def _install_oci(archive, rootfs):
    fd = os.open(rootfs, os.O_RDONLY)
    try:
        return install_local.install_from_local_file(str(archive), fd, "x86_64")
    finally:
        os.close(fd)


def _cached_blob(layer_blob):
    return Path(cache.layer_cache_path(layer_blob["digest"]))


@pytest.mark.parametrize("corrupt,fallback", [("manifest", False), ("config", False), ("layer", False), ("config", True)])
def test_oci_rejects_corrupt_blob_before_use_or_publication(oci, corrupt, fallback):
    archive, rootfs, base_cache = oci
    _write_oci(archive, _layer_bytes(b"expected"), corrupt=corrupt, fallback=fallback)

    with pytest.raises(RuntimeError, match="digest mismatch"):
        _install_oci(archive, rootfs)

    assert not list(rootfs.iterdir())
    assert not list(base_cache.glob("oci_layers/*"))


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("size", True, "invalid size"),
        ("size", -1, "invalid size"),
        ("size", 2**63, "invalid size"),
        ("size", 1, "size mismatch"),
        ("digest", "sha256:abcd", "SHA-256 digest"),
    ],
)
def test_oci_rejects_bad_layer_descriptor(oci, field, value, error):
    archive, rootfs, base_cache = oci
    layer = _layer_bytes(b"expected")
    descriptor = _descriptor(layer)
    descriptor[field] = value
    _write_oci(archive, layer, layer_descriptor=descriptor)

    with pytest.raises(RuntimeError, match=error):
        _install_oci(archive, rootfs)

    assert not list(base_cache.glob("oci_layers/*"))


@pytest.mark.parametrize("config", [[], {"architecture": []}, {"config": "invalid"}])
def test_oci_rejects_malformed_config_objects(oci, config):
    archive, rootfs, _ = oci
    _write_oci(archive, _layer_bytes(b"expected"), config=config)

    with pytest.raises(RuntimeError, match="JSON object|architecture|field 'config'"):
        _install_oci(archive, rootfs)


@pytest.mark.parametrize("member,corrupt", [("absent", None), ("symlink", None), ("regular", "layer")])
def test_oci_reuses_verified_cache_without_reading_archive_layer(oci, member, corrupt):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer, member=member, corrupt=corrupt))
    cached.parent.mkdir(parents=True)
    cached.write_bytes(layer)

    result = _install_oci(archive, rootfs)

    assert result["image_config"]["config"] is None
    assert (rootfs / "etc" / "fixture").read_bytes() == b"expected"


def test_oci_repairs_poisoned_cache_only_from_verified_archive(oci):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    wrong = _layer_bytes(b"poisoned")
    cached = _cached_blob(_write_oci(archive, layer, member="absent"))
    cached.parent.mkdir(parents=True)
    cached.write_bytes(wrong)

    with pytest.raises(RuntimeError, match="missing required file"):
        _install_oci(archive, rootfs)
    _write_oci(archive, layer, corrupt="layer")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        _install_oci(archive, rootfs)
    assert cached.read_bytes() == wrong
    assert not list(rootfs.iterdir())

    _write_oci(archive, layer)
    _install_oci(archive, rootfs)
    assert cached.read_bytes() == layer
    assert (rootfs / "etc" / "fixture").read_bytes() == b"expected"


@pytest.mark.parametrize("symlink_parent", ["cache", "oci_layers"])
def test_oci_refuses_symlinked_cache_parent(oci, tmp_path, symlink_parent):
    archive, rootfs, base_cache = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer))
    outside = tmp_path / "outside"
    outside.mkdir()
    if symlink_parent == "cache":
        link = base_cache
        decoy = outside / "oci_layers" / cached.name
        decoy.parent.mkdir()
    else:
        link = cached.parent
        decoy = outside / cached.name
    decoy.write_bytes(layer)
    link.parent.mkdir(parents=True)
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        _install_oci(archive, rootfs)
    assert not list(rootfs.iterdir())
    assert decoy.read_bytes() == layer


def test_oci_repairs_fifo_cache_leaf_without_opening_it_for_blocking_io(oci):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer))
    cached.parent.mkdir(parents=True)
    os.mkfifo(cached)

    _install_oci(archive, rootfs)

    assert cached.read_bytes() == layer
    assert (rootfs / "etc" / "fixture").read_bytes() == b"expected"


def test_oci_extracts_the_verified_inode_after_cache_name_is_replaced(oci, monkeypatch):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer))
    extract = install_local.extract_tar_stream

    def replace_then_extract(*args, **kwargs):
        cached.unlink()
        cached.write_bytes(_layer_bytes(b"poisoned"))
        extract(*args, **kwargs)

    monkeypatch.setattr(install_local, "extract_tar_stream", replace_then_extract)
    _install_oci(archive, rootfs)

    assert (rootfs / "etc" / "fixture").read_bytes() == b"expected"


def test_oci_reverifies_cache_entry_after_publication(oci, monkeypatch):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer))
    publish = install_local._oci_cache_layer

    def publish_then_replace(*args):
        publish(*args)
        cached.unlink()
        cached.write_bytes(_layer_bytes(b"poisoned"))

    monkeypatch.setattr(install_local, "_oci_cache_layer", publish_then_replace)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        _install_oci(archive, rootfs)

    assert not list(rootfs.iterdir())


def test_oci_writer_archive_installs_with_empty_cache(oci):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"built")
    descriptor = _descriptor(layer)
    cached = _cached_blob(descriptor)
    cached.parent.mkdir(parents=True)
    cached.write_bytes(layer)
    platform = Platform("linux", "amd64")
    layers = [{**descriptor, "diff_id": descriptor["digest"]}]
    manifest, config = oci_writer.build_manifest_and_config({}, layers, platform)
    result = PlatformResult(platform, manifest, config, layers)
    oci_writer.write_oci_archive(str(archive), [result], "fixture:latest")
    cached.unlink()

    metadata = _install_oci(archive, rootfs)

    assert metadata["image_ref"] == "fixture:latest"
    assert (rootfs / "etc" / "fixture").read_bytes() == b"built"
    assert cached.read_bytes() == layer


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

