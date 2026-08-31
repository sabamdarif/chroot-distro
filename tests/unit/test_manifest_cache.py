# The manifest cache is addressed by the whole platform, not by an architecture
# name: an entry decides what a container or a build stage stands on, and the
# chroot-distro arch name collapses every `arm` variant onto one. What is read
# back is also held to the platform it was asked for, since on Termux the cache
# sits under the $PREFIX that is bound read-write into every non-isolated
# container and the entry standing under a key need not be one this program wrote.

import json

import pytest

from chroot_distro.arch import Platform, parse_platform
from chroot_distro.helpers.docker import cache as cache_mod

ARM64 = Platform("linux", "arm64")
ARM_V7 = Platform("linux", "arm", "v7")
ARM = Platform("linux", "arm")
MANIFEST = {"layers": [{"digest": "sha256:" + "1a" * 32, "size": 3}]}


@pytest.fixture(autouse=True)
def cache_dir(tmp_path, monkeypatch):
    root = tmp_path / "oci_manifests"
    root.mkdir()
    monkeypatch.setattr(cache_mod, "MANIFEST_CACHE_DIR", str(root))
    return root


def _save(image_ref, platform, image_config=None):
    cache_mod.save_manifest_cache(image_ref, platform, MANIFEST, "library/alpine", image_config or {})


# ── what the key separates ────────────────────────────────────────────────────
def test_two_platforms_are_two_entries():
    assert cache_mod.manifest_cache_path("alpine", ARM64) != cache_mod.manifest_cache_path("alpine", ARM)


def test_an_arm_variant_is_an_entry_of_its_own():
    assert cache_mod.manifest_cache_path("alpine", ARM_V7) != cache_mod.manifest_cache_path("alpine", ARM)


@pytest.mark.parametrize("spelling", ["linux/arm64", "linux/aarch64", "arm64", "aarch64"])
def test_one_platform_has_one_key_however_it_was_spelled(spelling):
    assert cache_mod.manifest_cache_path("alpine", parse_platform(spelling)) == cache_mod.manifest_cache_path(
        "alpine", ARM64
    )


def test_a_reference_has_one_key_however_it_was_spelled():
    for ref in ("alpine:latest", "docker.io/library/alpine:latest", "index.docker.io/library/alpine"):
        assert cache_mod.manifest_cache_path(ref, ARM64) == cache_mod.manifest_cache_path("alpine", ARM64)


# ── the round trip ────────────────────────────────────────────────────────────
def test_a_saved_entry_records_its_platform_and_loads_back():
    _save("alpine", ARM_V7, {"architecture": "arm", "variant": "v7", "os": "linux"})

    manifest, repo, image_config = cache_mod.load_manifest_cache("alpine", ARM_V7)
    assert manifest == MANIFEST
    assert repo == "library/alpine"
    assert image_config["architecture"] == "arm"
    with open(cache_mod.manifest_cache_path("alpine", ARM_V7)) as fh:
        assert json.load(fh)["platform"] == "linux/arm/v7"


def test_another_platform_is_a_miss():
    _save("alpine", ARM64)

    assert cache_mod.load_manifest_cache("alpine", ARM) == (None, None, {})


def test_nothing_cached_is_a_miss():
    assert cache_mod.load_manifest_cache("alpine", ARM64) == (None, None, {})


@pytest.mark.parametrize("body", ["not json{{", "[]", '{"repo": "library/alpine"}', '{"manifest": {}}'])
def test_a_malformed_entry_is_a_miss(cache_dir, body):
    path = cache_mod.manifest_cache_path("alpine", ARM64)
    (cache_dir / path.rsplit("/", 1)[-1]).write_text(body)

    assert cache_mod.load_manifest_cache("alpine", ARM64) == (None, None, {})


# ── an entry that answers for another platform ────────────────────────────────
def test_an_entry_recording_another_platform_is_not_believed(cache_dir):
    path = cache_mod.manifest_cache_path("alpine", ARM64)
    (cache_dir / path.rsplit("/", 1)[-1]).write_text(
        json.dumps({"manifest": MANIFEST, "repo": "library/alpine", "platform": "linux/amd64"})
    )

    assert cache_mod.load_manifest_cache("alpine", ARM64) == (None, None, {})


def test_an_image_config_for_another_architecture_is_not_believed():
    _save("alpine", ARM64, {"architecture": "amd64", "os": "linux"})

    assert cache_mod.load_manifest_cache("alpine", ARM64) == (None, None, {})


def test_an_image_config_for_another_variant_is_not_believed():
    _save("alpine", ARM_V7, {"architecture": "arm", "variant": "v6"})

    assert cache_mod.load_manifest_cache("alpine", ARM_V7) == (None, None, {})


def test_an_image_config_that_declares_nothing_is_fine():
    # A pull whose config blob could not be fetched stores an empty one, and a
    # rootfs without image metadata is still usable.
    _save("alpine", ARM64, {})

    assert cache_mod.load_manifest_cache("alpine", ARM64)[0] == MANIFEST


# ── the key that came before ──────────────────────────────────────────────────
def test_an_entry_under_the_old_architecture_key_is_still_read(cache_dir):
    # `build` stored the only record of the image it produced there, and `push`
    # has nothing else to find it by.
    legacy = cache_mod._legacy_manifest_cache_path("myapp:1.0", "aarch64")
    (cache_dir / legacy.rsplit("/", 1)[-1]).write_text(json.dumps({"manifest": MANIFEST, "repo": "library/myapp"}))

    manifest, repo, _ = cache_mod.load_manifest_cache("myapp:1.0", ARM64)
    assert manifest == MANIFEST
    assert repo == "library/myapp"


def test_a_save_only_writes_the_platform_key(cache_dir):
    _save("myapp:1.0", ARM64)

    written = sorted(p.name for p in cache_dir.iterdir())
    assert written == [cache_mod.manifest_cache_path("myapp:1.0", ARM64).rsplit("/", 1)[-1]]
