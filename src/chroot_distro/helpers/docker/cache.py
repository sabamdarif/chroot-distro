# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The content-addressed blob cache and the manifest cache, addressed by name.

A digest arrives inside a registry document and then becomes a filename, so
`validate_digest` guards every path this module builds: the algorithm and hex form are
checked before `:` is rewritten to `_`, and a malformed digest raises instead of
reaching the filesystem. `layer_cache_path` is therefore the same path for the same
blob from any image, which is what lets two images share a layer.

The manifest key is a sha256 of the canonical `registry/repo:tag_arch` string, so a
reference has one spelling per architecture no matter how the user typed it. The key is
over the *tag*, not a digest, so re-pulling a moved tag overwrites the entry, which is
the intended behaviour.

`load_manifest_cache` reports any failure as a miss, because a re-fetch is always
correct. `referenced_blob_digests` is the opposite and fails closed: it returns the
paths it could not parse alongside the digests it found, and a caller pruning the layer
cache has to stop on a non-empty *unreadable* rather than read it as an absence of
references. Only `<key>.json` entries are read, since an `atomic_write` temporary is
half a file by definition.
"""

import hashlib
import json
import os
import re

from chroot_distro.atomic import atomic_write
from chroot_distro.constants import LAYER_CACHE_DIR, MANIFEST_CACHE_DIR
from chroot_distro.helpers.docker.refs import parse_image_ref

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


def manifest_cache_path(image_ref: str, arch: str) -> str:
    """Return the manifest-cache path for (*image_ref*, *arch*)."""
    registry, repo, tag = parse_image_ref(image_ref)
    canonical = f"{registry + '/' if registry else ''}{repo}:{tag}_{arch}"
    key = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return os.path.join(MANIFEST_CACHE_DIR, key + ".json")


def save_manifest_cache(
    image_ref: str,
    arch: str,
    manifest: dict,
    repo: str,
    image_config: dict,
) -> None:
    """Persist a manifest + image-config pair under the canonical cache key."""
    payload = {"manifest": manifest, "repo": repo, "image_config": image_config}
    with atomic_write(manifest_cache_path(image_ref, arch)) as fh:
        json.dump(payload, fh)


def load_manifest_cache(image_ref: str, arch: str):
    """Return (manifest, repo, image_config) from cache.

    On a cache miss (or read/parse error) returns ``(None, None, {})``.
    """
    try:
        with open(manifest_cache_path(image_ref, arch)) as fh:
            data = json.load(fh)
        return data["manifest"], data["repo"], data.get("image_config", {})
    except (OSError, json.JSONDecodeError, KeyError):
        return None, None, {}


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
