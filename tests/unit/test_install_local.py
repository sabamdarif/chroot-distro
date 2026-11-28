import gzip
import hashlib
import io
import json
import os
import shutil
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
from chroot_distro.commands import install, install_local
from chroot_distro.helpers import oci_writer
from chroot_distro.helpers.build_engine import PlatformResult
from chroot_distro.helpers.docker import cache
from chroot_distro.helpers.docker.media import OCI_INDEX_MEDIA, OCI_MANIFEST_MEDIA


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
    archive, layer, *, corrupt=None, member="regular", layer_descriptor=None, fallback=False, config=None, ref=None
):
    if config is None:
        config = {"architecture": "amd64", "os": "linux", "config": None}
    config_bytes = json.dumps(config).encode()
    config_blob = _descriptor(config_bytes)
    layer_blob = _descriptor(layer) if layer_descriptor is None else layer_descriptor
    manifest_bytes = json.dumps({"config": config_blob, "layers": [layer_blob]}).encode()
    manifest_blob = _descriptor(manifest_bytes)
    if ref is not None:
        manifest_blob["annotations"] = {"org.opencontainers.image.ref.name": ref}
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


def _install_archive(archive, rootfs, arch="x86_64", *, require_platform=False):
    fd = os.open(rootfs, os.O_RDONLY)
    try:
        return install_local.install_from_local_file(str(archive), fd, arch, require_platform=require_platform)
    finally:
        os.close(fd)


def _cached_blob(layer_blob):
    return Path(cache.layer_cache_path(layer_blob["digest"]))


def _write_index(archive, images, *, mode="w", late=False, prefix="", nested=False):
    with tarfile.open(archive, mode) as tf:
        def add_blob(data, **metadata):
            descriptor = _descriptor(data) | metadata
            _add_bytes(tf, prefix + _blob_path(descriptor), data)
            return descriptor

        entries = []
        for payload, declared, actual in images:
            layer = add_blob(_layer_bytes(payload))
            config = add_blob(json.dumps(actual).encode())
            manifest = json.dumps({"config": config, "layers": [layer]}).encode()
            fields = {} if declared is None else {"platform": declared}
            entries.append(add_blob(manifest, mediaType=OCI_MANIFEST_MEDIA, **fields))
        if nested:
            inner = add_blob(json.dumps({"manifests": entries[2:]}).encode(), mediaType=OCI_INDEX_MEDIA)
            inner["annotations"] = {"org.opencontainers.image.ref.name": "example.com/image:v7"}
            entries[2:] = [inner]
            entries.insert(0, {"mediaType": "application/example.artifact"})
        if late:
            for i in range(501):
                _add_bytes(tf, f"filler-{i}", b"")
        _add_bytes(tf, prefix + "index.json", json.dumps({"manifests": entries}).encode())
        _add_bytes(tf, prefix + "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')


@pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz", "w:zst"])
def test_late_dot_prefixed_oci_layout_installs(oci, mode):
    archive, rootfs, _ = oci
    platform = {"os": "linux", "architecture": "amd64"}
    _write_index(archive, [(b"image", platform, platform)], mode=mode, late=True, prefix="./")

    assert _install_archive(archive, rootfs)["arch"] == "x86_64"
    assert (rootfs / "etc" / "fixture").read_bytes() == b"image"
    assert not (rootfs / "oci-layout").exists()


def test_nested_oci_index_prefers_explicit_arm_v7(oci):
    archive, rootfs, _ = oci
    arm = {"os": "linux", "architecture": "arm"}
    v6, v7 = arm | {"variant": "v6"}, arm | {"variant": "v7"}
    windows = {"os": "windows", "architecture": "arm", "variant": "v7"}
    _write_index(archive, [(b"v6", v6, v6), (b"unspecified", None, arm),
                           (b"windows", windows, windows), (b"v7", v7, v7)], nested=True)

    result = _install_archive(archive, rootfs, "arm", require_platform=True)
    assert result["arch"] == "arm"
    assert result["image_config"]["variant"] == "v7"
    assert result["image_ref"] == "example.com/image:v7"
    assert (rootfs / "etc" / "fixture").read_bytes() == b"v7"


@pytest.mark.parametrize("declared,actual,error", [
    ({"os": "windows", "architecture": "amd64"}, {"os": "windows", "architecture": "amd64"}, "No supported Linux"),
    (None, {"os": "windows", "architecture": "amd64"}, "No supported Linux"),
    ({"os": "linux", "architecture": "amd64"}, {"os": "linux", "architecture": "arm64"}, "disagrees.*architecture"),
    ({"os": "linux", "architecture": "amd64"}, {"os": "windows", "architecture": "amd64"}, "disagrees.*os"),
])
def test_oci_requires_consistent_linux_platform(oci, declared, actual, error):
    archive, rootfs, _ = oci
    _write_index(archive, [(b"image", declared, actual)])

    with pytest.raises(RuntimeError, match=error):
        _install_archive(archive, rootfs)
    assert not list(rootfs.iterdir())


def test_single_foreign_oci_image_requires_matching_explicit_architecture(oci):
    archive, rootfs, _ = oci
    platform = {"os": "linux", "architecture": "arm64", "variant": "v8"}
    _write_index(archive, [(b"foreign", platform, platform)])

    with pytest.raises(RuntimeError, match="No supported Linux image for 'linux/amd64'"):
        _install_archive(archive, rootfs, require_platform=True)
    assert _install_archive(archive, rootfs)["arch"] == "aarch64"
    assert (rootfs / "etc" / "fixture").read_bytes() == b"foreign"


def test_oci_checks_outer_gzip_trailer_before_extracting_layers(oci):
    archive, rootfs, base_cache = oci
    _write_oci(archive, _layer_bytes(b"image"))
    archive.write_bytes(gzip.compress(archive.read_bytes())[:-8])

    with pytest.raises(tarfile.ReadError, match="compressed tar"):
        _install_archive(archive, rootfs)
    assert not list(rootfs.iterdir())
    assert not list(base_cache.glob("oci_layers/*"))


@pytest.mark.parametrize(
    "ref, expected_ref",
    [(None, ""), ("example.com/fixture:release.tar", "example.com/fixture:release.tar"),
     ("https://user:private@example.com/file?signature=annotation", "")],
)
def test_url_oci_install_saves_registry_tag_without_download_url(oci, tmp_path, monkeypatch, ref, expected_ref):
    archive, _, base_cache = oci
    url = "https://user:private@example.com/archive.oci.tar?token=query-token#fragment-token"
    config = {"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/bin/sh"]}}
    layer = _write_oci(archive, _layer_bytes(b"fixture"), config=config, ref=ref)
    containers = tmp_path / "containers"
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))
    monkeypatch.setattr(install, "BASE_CACHE_DIR", str(base_cache))
    monkeypatch.setattr(install, "IS_TERMUX", False)
    monkeypatch.setattr(install, "write_hosts", MagicMock())
    monkeypatch.setattr(install, "write_resolv_conf", MagicMock())

    def download(request_url, destination, *, insecure):
        assert request_url == url
        shutil.copyfile(archive, destination)

    monkeypatch.setattr(install, "download_file", download)
    install._run_install("box", url, None, url, "x86_64")

    payload = (containers / "box" / "manifest.json").read_text(encoding="utf-8")
    assert all(secret not in payload for secret in ("private", "query-token", "fragment-token", "signature="))
    metadata = json.loads(payload)
    assert metadata["image_ref"] == expected_ref
    assert metadata["manifest"]["layers"] == [layer]
    assert metadata["image_config"] == config
    assert metadata["arch"] == "x86_64"


@pytest.mark.parametrize("corrupt,fallback", [("manifest", False), ("config", False), ("layer", False), ("config", True)])
def test_oci_rejects_corrupt_blob_before_use_or_publication(oci, corrupt, fallback):
    archive, rootfs, base_cache = oci
    _write_oci(archive, _layer_bytes(b"expected"), corrupt=corrupt, fallback=fallback)

    with pytest.raises(RuntimeError, match="digest mismatch"):
        _install_archive(archive, rootfs)

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
        _install_archive(archive, rootfs)

    assert not list(base_cache.glob("oci_layers/*"))


@pytest.mark.parametrize("config", [[], {"architecture": []}, {"config": "invalid"}])
def test_oci_rejects_malformed_config_objects(oci, config):
    archive, rootfs, _ = oci
    _write_oci(archive, _layer_bytes(b"expected"), config=config)

    with pytest.raises(RuntimeError, match="JSON object|architecture|field 'config'"):
        _install_archive(archive, rootfs)


@pytest.mark.parametrize("member,corrupt", [("absent", None), ("symlink", None), ("regular", "layer")])
def test_oci_reuses_verified_cache_without_reading_archive_layer(oci, member, corrupt):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer, member=member, corrupt=corrupt))
    cached.parent.mkdir(parents=True)
    cached.write_bytes(layer)

    result = _install_archive(archive, rootfs)

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
        _install_archive(archive, rootfs)
    _write_oci(archive, layer, corrupt="layer")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        _install_archive(archive, rootfs)
    assert cached.read_bytes() == wrong
    assert not list(rootfs.iterdir())

    _write_oci(archive, layer)
    _install_archive(archive, rootfs)
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
        _install_archive(archive, rootfs)
    assert not list(rootfs.iterdir())
    assert decoy.read_bytes() == layer


def test_oci_repairs_fifo_cache_leaf_without_opening_it_for_blocking_io(oci):
    archive, rootfs, _ = oci
    layer = _layer_bytes(b"expected")
    cached = _cached_blob(_write_oci(archive, layer))
    cached.parent.mkdir(parents=True)
    os.mkfifo(cached)

    _install_archive(archive, rootfs)

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
    _install_archive(archive, rootfs)

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
        _install_archive(archive, rootfs)

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

    metadata = _install_archive(archive, rootfs)

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


@pytest.mark.parametrize(("mode", "wrapper"), [("w", "backup"), ("w:gz", "backup with spaces")])
def test_install_backup_filters_members_and_hardlinks_by_rootfs_prefix(tmp_path, mode, wrapper):
    archive = tmp_path / "backup.tar"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    with tarfile.open(archive, mode) as tf:
        _add_bytes(tf, "unrelated/manifest.json", b'{"image_ref":"wrong"}')
        _add_bytes(tf, f"./{wrapper}/manifest.json", b'{"image_ref":"expected"}')
        _add_bytes(tf, "other/tree/etc/outside", b"outside")
        _add_bytes(tf, f"{wrapper}/rootfs-extra/etc/outside", b"also outside")
        _add_bytes(tf, f"/{wrapper}/rootfs/etc/inside", b"inside")

        for name, target, kind in (
            ("etc/copy", f"./{wrapper}/rootfs/etc/inside", tarfile.LNKTYPE),
            ("other/copy", "other/tree/etc/inside", tarfile.LNKTYPE),
            ("link", "/etc/inside", tarfile.SYMTYPE),
        ):
            entry = tarfile.TarInfo(f"{wrapper}/rootfs/{name}")
            entry.type = kind
            entry.linkname = target
            tf.addfile(entry)

    assert _install_archive(archive, rootfs) == {"image_ref": "expected"}
    assert sorted(path.name for path in rootfs.iterdir()) == ["etc", "link"]
    assert sorted(path.name for path in (rootfs / "etc").iterdir()) == ["copy", "inside"]
    assert (rootfs / "etc/inside").read_bytes() == (rootfs / "etc/copy").read_bytes() == b"inside"
    assert os.readlink(rootfs / "link") == "/etc/inside"


def test_install_backup_without_manifest_prefers_leading_rootfs(tmp_path):
    archive = tmp_path / "usr.tar"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    with tarfile.open(archive, "w") as tf:
        entry = tarfile.TarInfo("./usr/rootfs")
        entry.type = tarfile.DIRTYPE
        tf.addfile(entry)
        _add_bytes(tf, "usr/rootfs/etc/inside", b"inside")
        _add_bytes(tf, "other/manifest.json", b'{"image_ref":"wrong"}')
        _add_bytes(tf, "other/rootfs/etc/outside", b"outside")

    assert _install_archive(archive, rootfs) is None
    assert list(rootfs.iterdir()) == [rootfs / "etc"]
    assert list((rootfs / "etc").iterdir()) == [rootfs / "etc/inside"]
    assert (rootfs / "etc/inside").read_bytes() == b"inside"


def test_install_wrapped_plain_tar_keeps_strip_vote(tmp_path):
    archive = tmp_path / "plain.tar"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "./wrapper/manifest.json", b"{}")
        _add_bytes(tf, "./wrapper/etc/inside", b"inside")

    assert _install_archive(archive, rootfs) is None
    assert (rootfs / "manifest.json").read_bytes() == b"{}"
    assert (rootfs / "etc/inside").read_bytes() == b"inside"


def test_install_backup_keeps_archive_open_between_passes(tmp_path, monkeypatch):
    archive = tmp_path / "backup.tar"
    replacement = tmp_path / "replacement.tar"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    with tarfile.open(archive, "w") as tf:
        _add_bytes(tf, "box/manifest.json", b'{"image_ref":"original"}')
        _add_bytes(tf, "box/rootfs/etc/inside", b"original")
    with tarfile.open(replacement, "w") as tf:
        _add_bytes(tf, "box/manifest.json", b'{"image_ref":"replacement"}')
        _add_bytes(tf, "box/rootfs/etc/inside", b"replacement")

    detect_backup = install_local._detect_backup

    def replace_archive(members):
        replacement.replace(archive)
        return detect_backup(members)

    monkeypatch.setattr(install_local, "_detect_backup", replace_archive)
    assert _install_archive(archive, rootfs) == {"image_ref": "original"}
    assert (rootfs / "etc/inside").read_bytes() == b"original"


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

