# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The content-addressed blob cache and the manifest cache, addressed by name.

A digest arrives inside a registry document and then becomes a filename, so
`validate_digest` guards every path this module builds: the algorithm and hex form are
checked before `:` is rewritten to `_`, and a malformed digest raises instead of
reaching the filesystem. `layer_cache_path` is therefore the same path for the same
blob from any image, which is what lets two images share a layer.

The manifest key is a sha256 of the canonical `registry/repo:tag_platform` string, so a
reference has one spelling per platform no matter how the user typed it, and
`linux/arm/v7` is not the same entry as another `arm` variant: the key carries the whole
platform because the entry decides what a container or a build stage stands on. The key
is over the *tag*, not a digest, so re-pulling a moved tag overwrites the entry, which is
the intended behaviour.

`load_manifest_cache` reports any failure as a miss, because a re-fetch is always
correct, and it holds an entry to the platform it was asked for twice over: against the
platform the entry recorded, and against the one its image config declares. An entry
written before the key carried the platform is still read, under the old
architecture-only key, because a `build` that ran then left the only record of the image
it produced there and `push` has nothing else to find it by; nothing is written back
under that name.

`referenced_blob_digests` is the opposite and fails closed: it returns the
paths it could not parse alongside the digests it found, and a caller pruning the layer
cache has to stop on a non-empty *unreadable* rather than read it as an absence of
references. Only `<key>.json` entries are read, since an `atomic_write` temporary is
half a file by definition.
"""

import hashlib
import json
import logging
import os
import re
import typing

from chroot_distro.arch import Platform
from chroot_distro.atomic import atomic_write
from chroot_distro.constants import LAYER_CACHE_DIR, MANIFEST_CACHE_DIR
from chroot_distro.helpers.docker.refs import parse_image_ref

log = logging.getLogger(__name__)

_DIGEST_RE = re.compile(r"^[A-Za-z0-9]+(?:[+_.\-][A-Za-z0-9]+)*:[A-Fa-f0-9]+$")


def is_valid_digest(digest: object) -> bool:
    """Return True when *digest* is a well-formed `algorithm:hex` digest.

    The predicate every reader of a digest that arrived in someone else's
    document wants: the build cache index refuses an entry whose layer digest is
    not one, rather than letting it reach a filename.
    """
    return isinstance(digest, str) and bool(_DIGEST_RE.match(digest))


def validate_digest(digest: str) -> str:
    """Return *digest* unchanged when well-formed; raise otherwise."""
    if not is_valid_digest(digest):
        raise RuntimeError(f"Malformed digest: {digest!r}")
    return digest


def layer_cache_path(digest: str) -> str:
    """Return the on-disk path of the cached blob for *digest*."""
    validate_digest(digest)
    return os.path.join(LAYER_CACHE_DIR, digest.replace(":", "_"))


def manifest_cache_path(image_ref: str, platform: Platform) -> str:
    """Return the manifest-cache path for (*image_ref*, *platform*)."""
    return _manifest_cache_path(image_ref, platform.format())


def _legacy_manifest_cache_path(image_ref: str, arch_pd: str) -> str:
    """The pre-platform key: the same string with the chroot-distro arch name."""
    return _manifest_cache_path(image_ref, arch_pd)


def _manifest_cache_path(image_ref: str, suffix: str) -> str:
    registry, repo, tag = parse_image_ref(image_ref)
    canonical = f"{registry + '/' if registry else ''}{repo}:{tag}_{suffix}"
    key = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return os.path.join(MANIFEST_CACHE_DIR, key + ".json")


def save_manifest_cache(
    image_ref: str,
    platform: Platform,
    manifest: dict,
    repo: str,
    image_config: dict,
) -> None:
    """Persist a manifest + image-config pair under the canonical cache key."""
    payload = {
        "manifest": manifest,
        "repo": repo,
        "image_config": image_config,
        "platform": platform.format(),
    }
    with atomic_write(manifest_cache_path(image_ref, platform)) as fh:
        json.dump(payload, fh)


def load_manifest_cache(image_ref: str, platform: Platform) -> tuple[dict[str, typing.Any] | None, str | None, dict[str, typing.Any]]:
    """Return (manifest, repo, image_config) from cache.

    On a cache miss (or read/parse error) returns ``(None, None, {})``. An entry
    that does not answer for *platform* is a miss too: the key already carries the
    platform, so what this catches is an entry composed by someone else, which on
    Termux is anything with write access to the bound $PREFIX. The old
    architecture-only key is read as a fallback, for an image built before the key
    carried the platform.
    """
    candidates = (
        (manifest_cache_path(image_ref, platform), True),
        (_legacy_manifest_cache_path(image_ref, platform.to_arch()), False),
    )
    for path, check_recorded in candidates:
        try:
            with open(path) as fh:
                data = json.load(fh)
            manifest, repo = data["manifest"], data["repo"]
            image_config = data.get("image_config") or {}
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            continue
        recorded = data.get("platform")
        if check_recorded and isinstance(recorded, str) and recorded != platform.format():
            log.debug("Ignoring %s: it records platform %s, not %s", path, recorded, platform)
            continue
        if not _config_is_for(image_config, platform):
            log.debug("Ignoring %s: its image config is not for %s", path, platform)
            continue
        return manifest, repo, image_config
    return None, None, {}


def _config_is_for(image_config: typing.Any, platform: Platform) -> bool:
    """True unless a cached image config declares a platform other than *platform*.

    Only what the document actually says is checked: a config carries `os` and
    `architecture` and rarely a `variant`, and a pull whose config blob could not
    be fetched stores an empty one, so an absent field is not a mismatch. What is
    a mismatch is an entry for one platform standing under another's key.
    """
    if not isinstance(image_config, dict):
        return False
    declared = {
        "os": platform.os,
        "architecture": platform.architecture,
        "variant": platform.variant,
    }
    for key, expected in declared.items():
        value = image_config.get(key)
        if isinstance(value, str) and value and expected and value != expected:
            return False
    return True


def referenced_blob_digests() -> tuple[set[str], list[str]]:
    """Return (digests, unreadable) covering every cached image's blobs.

    *digests* is every blob digest the manifest cache names (the layers and
    the config descriptor, so an entry stays covered if a config blob ever
    reaches the layer cache as well). *unreadable* lists the entry paths
    that could not be parsed.

    A caller pruning the layer cache has to treat a non-empty *unreadable* as a
    reason to stop rather than as an absence of references: one truncated
    manifest would otherwise make every layer of an image the user still has
    look collectable. Only '<key>.json' entries are read: `atomic_write`'s
    in-flight temporaries carry a '.tmp' suffix and are half a file by
    definition.
    """
    digests: set[str] = set()
    unreadable: list[str] = []
    try:
        names = sorted(os.listdir(MANIFEST_CACHE_DIR))
    except FileNotFoundError:
        return digests, unreadable
    except OSError:
        return digests, [MANIFEST_CACHE_DIR]

    for fname in names:
        if not fname.endswith(".json"):
            continue
        path = os.path.join(MANIFEST_CACHE_DIR, fname)
        try:
            with open(path) as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            unreadable.append(path)
            continue
        manifest = payload.get("manifest") if isinstance(payload, dict) else None
        if not isinstance(manifest, dict):
            unreadable.append(path)
            continue
        descriptors = list(manifest.get("layers") or [])
        descriptors.append(manifest.get("config"))
        for descriptor in descriptors:
            if isinstance(descriptor, dict) and descriptor.get("digest"):
                digests.add(descriptor["digest"])
    return digests, unreadable


def all_layers_cached(layers: list) -> bool:
    """Return True iff every layer's blob file is already on disk."""
    return all(os.path.isfile(layer_cache_path(layer["digest"])) for layer in layers)
