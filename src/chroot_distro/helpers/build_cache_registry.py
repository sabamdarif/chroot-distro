# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The registry backend for the build-step cache: push it, pull it back.

`--cache-to type=registry,ref=...` and `--cache-from type=registry,ref=...` move
the same document `build_cache_io` writes to a directory, stored in a registry as
one OCI artifact instead of a folder. The document does not change: the local
directory is staged with `export_cache`, packed into a single gzipped tar, pushed
as the artifact's one layer blob, and on the way back fetched and unpacked into a
directory that `import_cache` reads. The format stays this program's own, so the
two backends are interchangeable and neither translates anything.

The artifact is deliberately minimal: an empty config (registries require one,
and a cache has no config), one layer whose media type names the payload, and a
manifest whose `artifactType` marks it as not an image. A registry that does not
list `artifactType` still stores the manifest, since it is an ordinary OCI image
manifest with an unusual config and layer.

Push order is the registry's rule, the same one `push.py` states: config and
layer blobs first, the manifest last. Pull verifies the blob against the digest
that names it through `download_blob` before a byte of it is trusted, and the
unpacked entries are then held to `import_cache`'s own checks, so a corrupt or
hostile artifact costs a rebuild rather than a poisoned cache.
"""

import hashlib
import os
import tarfile
import tempfile
import typing
import urllib.error

from chroot_distro.helpers import build_cache_io
from chroot_distro.helpers.docker.layers import download_blob
from chroot_distro.helpers.docker.media import canonical_json
from chroot_distro.helpers.docker.pull import _get_manifest
from chroot_distro.helpers.docker.push import (
    _blob_exists,
    _put_manifest,
    _upload_blob_bytes,
)
from chroot_distro.helpers.docker.refs import parse_image_ref
from chroot_distro.helpers.docker.transport import (
    auth_note,
    get_auth_token,
    push_denied_msg,
    registry_base_url,
)
from chroot_distro.message import log_info

# The payload is the cache directory as one gzipped tar: build-cache.json plus
# blobs/. The media types name it as something other than an image layer, so a
# registry or a puller does not mistake the artifact for a runnable image.
_CACHE_LAYER_MEDIA = "application/vnd.chroot-distro.buildcache.v1.tar+gzip"
_CACHE_ARTIFACT_TYPE = "application/vnd.chroot-distro.buildcache.v1+json"
# A cache has no config; registries require the descriptor, so it points at an
# empty JSON object.
_EMPTY_CONFIG = b"{}"
_EMPTY_CONFIG_DIGEST = "sha256:" + hashlib.sha256(_EMPTY_CONFIG).hexdigest()
_EMPTY_CONFIG_MEDIA = "application/vnd.oci.empty.v1+json"


def push_cache(ref: str, recipes: typing.Iterable[str], insecure: bool = False) -> tuple[int, int]:
    """Push the cache entries for *recipes* to the registry *ref* names.

    Stages the local document with `export_cache`, packs it into one blob, and
    uploads config, blob and manifest. Returns (steps, payload bytes), the same
    shape `export_cache` reports.
    """
    registry, repo, tag = parse_image_ref(ref)
    if not repo:
        raise RuntimeError(f"cache reference '{ref}' does not name a repository.")

    with tempfile.TemporaryDirectory(prefix="cd-cache-push-") as stage:
        steps, _size = build_cache_io.export_cache(stage, recipes)
        blob = _pack_directory(stage)

    with open(blob, "rb") as fh:
        blob_bytes = fh.read()
    blob_digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
    os.unlink(blob)

    log_info(f"Authenticating with registry{auth_note()}...")
    token, base = get_auth_token(repo, registry, actions="pull,push", insecure=insecure)
    base = base or registry_base_url(registry, insecure=insecure)

    try:
        if not _blob_exists(repo, _EMPTY_CONFIG_DIGEST, token, base, insecure=insecure):
            _upload_blob_bytes(repo, _EMPTY_CONFIG_DIGEST, _EMPTY_CONFIG, token, base, insecure=insecure)
        if not _blob_exists(repo, blob_digest, token, base, insecure=insecure):
            log_info(f"Uploading the build cache ({len(blob_bytes)} bytes, {steps} step(s))...")
            _upload_blob_bytes(repo, blob_digest, blob_bytes, token, base, insecure=insecure)
        else:
            log_info("The build cache blob is already on the registry.")

        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": _CACHE_ARTIFACT_TYPE,
            "config": {
                "mediaType": _EMPTY_CONFIG_MEDIA,
                "digest": _EMPTY_CONFIG_DIGEST,
                "size": len(_EMPTY_CONFIG),
            },
            "layers": [
                {
                    "mediaType": _CACHE_LAYER_MEDIA,
                    "digest": blob_digest,
                    "size": len(blob_bytes),
                }
            ],
        }
        media = manifest["mediaType"]
        _put_manifest(repo, tag, canonical_json(manifest), str(media), token, base, insecure=insecure)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(push_denied_msg(ref, exc.code)) from exc
        raise
    return steps, len(blob_bytes)


def pull_cache(ref: str, insecure: bool = False) -> tuple[int, int]:
    """Fetch the cache artifact *ref* names and merge it into the local cache.

    Returns (steps added, entries refused), the shape `import_cache` reports. The
    blob is fetched and verified against its digest before it is unpacked, and
    `import_cache` then verifies each entry's blob against its own digest and
    diff_id, so the artifact is held to the same standard as a local directory.
    """
    registry, repo, tag = parse_image_ref(ref)
    if not repo:
        raise RuntimeError(f"cache reference '{ref}' does not name a repository.")

    log_info(f"Authenticating with registry{auth_note()}...")
    token, base = get_auth_token(repo, registry, insecure=insecure)
    base = base or registry_base_url(registry, insecure=insecure)

    log_info(f"Fetching the build cache manifest for '{ref}'...")
    manifest = _get_manifest(repo, tag, token, base, insecure=insecure)
    layers = manifest.get("layers", [])
    if len(layers) != 1:
        raise RuntimeError(
            f"'{ref}' is not a build cache this program wrote (expected one layer, found {len(layers)})."
        )
    digest = layers[0]["digest"]

    log_info("Downloading the build cache blob...")
    blob_path = download_blob(repo, digest, token, base, insecure=insecure)

    with tempfile.TemporaryDirectory(prefix="cd-cache-pull-") as stage:
        _unpack_directory(blob_path, stage)
        return build_cache_io.import_cache(stage)


def _pack_directory(stage: str) -> str:
    """Pack *stage* (build-cache.json + blobs/) into one gzipped tar; return its path."""
    out = stage + ".tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        for name in (build_cache_io.INDEX_NAME, build_cache_io.BLOBS_NAME):
            full = os.path.join(stage, name)
            if os.path.exists(full):
                tf.add(full, arcname=name)
    return out


def _unpack_directory(blob_path: str, stage: str) -> None:
    """Unpack the cache blob into *stage*, dropping anything outside it."""
    with tarfile.open(blob_path, "r:*") as tf:
        for member in tf.getmembers():
            # The blob is nobody's to vouch for: only plain files under the two
            # names the format holds are extracted, and no member may climb out.
            name = member.name.lstrip("./")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            if not (name == build_cache_io.INDEX_NAME or name.startswith(build_cache_io.BLOBS_NAME + "/")):
                continue
            if not (member.isreg() or member.isdir()):
                continue
            tf.extract(member, stage, filter="data")
