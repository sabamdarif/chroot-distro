# What an archive says about the platforms it holds.
#
# The index is what a consumer picks an image out of, so every descriptor names
# the platform its manifest was built for and they stand in the order the
# platforms were asked for. A config that disagrees with the descriptor pointing
# at it is the one error nothing downstream catches: a registry serves the image
# whose descriptor matched. The Docker-legacy `manifest.json` cannot describe more
# than one image, so it describes the first.

import dataclasses
import hashlib
import json
import tarfile

import pytest

from chroot_distro.arch import Platform
from chroot_distro.commands import install_local
from chroot_distro.helpers import oci_writer
from chroot_distro.helpers.build_engine import PlatformResult

AMD64 = Platform("linux", "amd64")
ARM64 = Platform("linux", "arm64")
ARMV7 = Platform("linux", "arm", "v7")


@pytest.fixture
def layer(tmp_path, monkeypatch):
    """Put a layer blob in the cache the writer packs out of, and describe it."""
    cache = tmp_path / "layers"
    cache.mkdir()
    monkeypatch.setattr(oci_writer, "layer_cache_path", lambda digest: str(cache / digest.replace(":", "_")))

    def add(data: bytes) -> dict:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        (cache / digest.replace(":", "_")).write_bytes(data)
        return {"digest": digest, "size": len(data), "diff_id": digest}

    return add


def _result(platform, layers=()):
    """One solve's output, built the way `solve_platform` builds one."""
    layers = list(layers)
    manifest, image_config = oci_writer.build_manifest_and_config({"config": {}, "history": []}, layers, platform)
    return PlatformResult(platform=platform, manifest=manifest, image_config=image_config, layers=layers)


def _read(path):
    """(index, legacy manifest, {blob arcname: bytes}, member names) of an archive."""
    with tarfile.open(path) as tf:
        names = tf.getnames()
        index = json.loads(tf.extractfile("index.json").read())
        legacy = json.loads(tf.extractfile("manifest.json").read())
        blobs = {name: tf.extractfile(name).read() for name in names if name.startswith("blobs/")}
    return index, legacy, blobs, names


def _blob(blobs, digest):
    return json.loads(blobs["blobs/sha256/" + digest.split(":", 1)[1]])


# ── one platform ──────────────────────────────────────────────────────────────
def test_a_descriptor_names_its_platform_and_addresses_its_own_manifest(tmp_path, layer):
    out = tmp_path / "img.tar"

    oci_writer.write_oci_archive(str(out), [_result(ARM64, [layer(b"one")])], "app:1")

    index, _legacy, blobs, names = _read(out)
    (descriptor,) = index["manifests"]
    assert names[0] == "oci-layout"
    assert descriptor["platform"] == {"architecture": "arm64", "os": "linux"}
    assert descriptor["annotations"]["org.opencontainers.image.ref.name"] == "app:1"
    assert descriptor["size"] == len(blobs["blobs/sha256/" + descriptor["digest"].split(":", 1)[1]])
    manifest = _blob(blobs, descriptor["digest"])
    assert _blob(blobs, manifest["config"]["digest"])["architecture"] == "arm64"


def test_a_variant_reaches_the_descriptor_and_the_config(tmp_path, layer):
    out = tmp_path / "img.tar"

    oci_writer.write_oci_archive(str(out), [_result(ARMV7)], "app:1")

    index, _legacy, blobs, _names = _read(out)
    (descriptor,) = index["manifests"]
    assert descriptor["platform"] == {"architecture": "arm", "os": "linux", "variant": "v7"}
    assert _blob(blobs, _blob(blobs, descriptor["digest"])["config"]["digest"])["variant"] == "v7"


def test_the_platform_replaces_a_base_image_variant():
    # A base pulled for linux/arm/v7 carries that variant in its config, and a
    # build of another platform from it must not publish the one it inherited.
    _manifest, config = oci_writer.build_manifest_and_config(
        {"architecture": "arm", "variant": "v7", "os": "linux", "history": []}, [], ARM64
    )

    assert config["architecture"] == "arm64"
    assert config["os"] == "linux"
    assert "variant" not in config


# ── a matrix ──────────────────────────────────────────────────────────────────
def test_every_platform_gets_a_manifest_and_a_config_in_the_order_asked_for(tmp_path, layer):
    out = tmp_path / "img.tar"
    results = [_result(AMD64, [layer(b"amd")]), _result(ARM64, [layer(b"arm")]), _result(ARMV7)]

    oci_writer.write_oci_archive(str(out), results, "app:1")

    index, _legacy, blobs, _names = _read(out)
    assert [d["platform"]["architecture"] for d in index["manifests"]] == ["amd64", "arm64", "arm"]
    for descriptor, result in zip(index["manifests"], results, strict=True):
        manifest = _blob(blobs, descriptor["digest"])
        config = _blob(blobs, manifest["config"]["digest"])
        assert config["architecture"] == result.platform.architecture
        assert manifest["layers"] == result.manifest["layers"]
        assert descriptor["annotations"]["org.opencontainers.image.ref.name"] == "app:1"


def test_a_layer_two_platforms_share_is_packed_once(tmp_path, layer):
    out = tmp_path / "img.tar"
    shared = layer(b"shared")

    oci_writer.write_oci_archive(str(out), [_result(AMD64, [shared]), _result(ARM64, [shared])], "app:1")

    _index, _legacy, blobs, names = _read(out)
    assert names.count("blobs/sha256/" + shared["digest"].split(":", 1)[1]) == 1
    # Two manifests, two configs, one layer: the platforms differ, so only the
    # blob whose bytes they both produced is the same entry.
    assert len(blobs) == 5


def test_our_own_installer_picks_a_platform_out_of_the_index(tmp_path, layer):
    out = tmp_path / "img.tar"

    oci_writer.write_oci_archive(str(out), [_result(AMD64, [layer(b"amd")]), _result(ARM64, [layer(b"arm")])], "app:1")

    index, _legacy, _blobs, _names = _read(out)
    with tarfile.open(out) as tf:
        member_map = {m.name: m for m in tf.getmembers()}
        for arch, expected in (("aarch64", "arm64"), ("x86_64", "amd64")):
            entry = install_local._oci_find_manifest_entry(tf, member_map, index["manifests"], arch)
            assert entry["platform"]["architecture"] == expected


# ── what a legacy loader is told ──────────────────────────────────────────────
def test_the_legacy_manifest_describes_the_first_platform_only(tmp_path, layer):
    out = tmp_path / "img.tar"
    first, second = layer(b"amd"), layer(b"arm")

    oci_writer.write_oci_archive(str(out), [_result(AMD64, [first]), _result(ARM64, [second])], "app:1")

    index, legacy, blobs, _names = _read(out)
    (entry,) = legacy
    first_manifest = _blob(blobs, index["manifests"][0]["digest"])
    assert entry["RepoTags"] == ["app:1"]
    assert entry["Layers"] == ["blobs/sha256/" + first["digest"].split(":", 1)[1]]
    assert entry["Config"] == "blobs/sha256/" + first_manifest["config"]["digest"].split(":", 1)[1]


# ── what the writer refuses ───────────────────────────────────────────────────
def test_a_config_for_another_platform_is_refused(tmp_path, layer):
    out = tmp_path / "img.tar"
    mislabelled = dataclasses.replace(_result(AMD64, [layer(b"amd")]), platform=ARM64)

    with pytest.raises(RuntimeError, match="declares architecture 'amd64', not the 'linux/arm64'"):
        oci_writer.write_oci_archive(str(out), [mislabelled], "app:1")


def test_no_result_is_no_archive(tmp_path):
    with pytest.raises(RuntimeError, match="No platform result"):
        oci_writer.write_oci_archive(str(tmp_path / "img.tar"), [], "app:1")


# ── the same images pack to the same bytes ────────────────────────────────────
def test_two_writes_of_one_matrix_are_byte_identical(tmp_path, layer):
    results = [_result(AMD64, [layer(b"amd")]), _result(ARM64, [layer(b"arm")])]
    first, second = tmp_path / "a.tar", tmp_path / "b.tar"

    oci_writer.write_oci_archive(str(first), results, "app:1")
    oci_writer.write_oci_archive(str(second), results, "app:1")

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first) as tf:
        assert {(m.mode, m.uid, m.gid, m.mtime) for m in tf.getmembers()} == {(0o644, 0, 0, 0)}
