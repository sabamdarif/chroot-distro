# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Turn finished solves into the documents a registry, `docker load`, and `install` read.

One config and one manifest per platform, and one index over all of them.
`build_manifest_and_config` is the per-platform half: it takes the whole platform
rather than an architecture name, so `os`, `architecture` and `variant` all come from
one value and a base image's own variant cannot outlive the platform it was adopted
for. It hashes the config with `canonical_json` and puts that digest in the manifest,
so the descriptor describes the exact bytes that will be shipped; `history` comes from
the engine verbatim, since it already appended one entry per dispatched instruction.
`store_in_cache` writes under the same key `helpers/docker/cache.py` computes, which is
the whole reason a `build` followed by an `install` of the same reference needs no
network.

`write_oci_archive` packages a whole matrix: one manifest and one config blob per
result, one `index.json` descriptor per result carrying the platform it was built for,
and each layer blob once however many platforms name it. A result whose config answers
for another platform than its descriptor claims is refused rather than published, since
a registry hands a puller the image whose descriptor matched and nothing downstream
checks the two against each other.

The archive carries a Docker-legacy `manifest.json` beside the OCI layout, because
`docker load` without one either refuses the archive or falls back to a legacy import
loop that misreads the layout. That format describes a single image, so for a matrix it
describes the first platform asked for and `index.json` answers for the rest.
`oci-layout` is the first member so this program's own format probe recognises the
archive on the entry it sees first, the blobs follow in name order, and every entry is
written with mode 0644, mtime 0 and uid/gid 0, so the same images package to the same
bytes.

A manifest whose config digest disagrees with the bytes about to be written is corrected
rather than published inconsistent, and a layer blob missing from the cache raises
instead of yielding a truncated archive.
"""

import hashlib
import json
import os
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import typing

from chroot_distro.arch import Platform
from chroot_distro.atomic import atomic_write
from chroot_distro.helpers.docker import (
    layer_cache_path,
    manifest_cache_path,
    parse_image_ref,
)
from chroot_distro.helpers.docker.media import (
    OCI_CONFIG_MEDIA,
    OCI_INDEX_MEDIA,
    OCI_LAYER_MEDIA,
    OCI_MANIFEST_MEDIA,
    canonical_json,
)

if typing.TYPE_CHECKING:
    from chroot_distro.helpers.build_engine.solve import PlatformResult


def build_manifest_and_config(
    image_config: dict[str, typing.Any],
    layers: list[dict[str, typing.Any]],
    platform: Platform,
) -> tuple[dict[str, typing.Any], dict[str, typing.Any]]:
    """Assemble one platform's OCI image manifest and image config blobs.

    `image_config` is the in-progress config dict managed by the
    build engine: its `history` array is taken verbatim (the engine
    appends one entry per dispatched instruction so the count of
    non-empty-layer entries already matches len(layers)). `layers` is
    the ordered list of {"digest", "size", "diff_id"} entries for
    this image.

    *platform* is what the image answers for, and `os`, `architecture` and
    `variant` are all written from it: a base image adopted from another platform
    brought its own along, and one left standing would describe the built image as
    something it is not.

    Returns (manifest_dict, image_config_dict). The image_config has the platform
    and `rootfs.diff_ids` populated and carries whatever `history` the engine
    produced.
    """
    config = dict(image_config)
    config["os"] = platform.os
    config["architecture"] = platform.architecture
    if platform.variant:
        config["variant"] = platform.variant
    else:
        config.pop("variant", None)
    config["rootfs"] = {
        "type": "layers",
        "diff_ids": [layer["diff_id"] for layer in layers],
    }
    # Defensive: every code path that reaches here is expected to have
    # populated history during dispatch. The setdefault is just so
    # tests / future callers that construct an image_config by hand
    # don't blow up on a missing key.
    config.setdefault("history", [])

    config_bytes = canonical_json(config)
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA,
        "config": {
            "mediaType": OCI_CONFIG_MEDIA,
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": OCI_LAYER_MEDIA,
                "digest": layer["digest"],
                "size": layer["size"],
            }
            for layer in layers
        ],
    }
    return manifest, config


def store_in_cache(
    image_ref: str,
    platform: Platform,
    manifest: dict[str, typing.Any],
    image_config: dict[str, typing.Any],
) -> str:
    """Write the manifest into MANIFEST_CACHE_DIR for offline install.

    The cache key and the recorded platform match what
    `helpers/docker/cache.py` writes and reads, which is the whole reason a
    `build` followed by an `install` of the same reference needs no network.
    """
    _, repo, _ = parse_image_ref(image_ref)
    path = manifest_cache_path(image_ref, platform)
    payload = {
        "manifest": manifest,
        "repo": repo,
        "image_config": image_config,
        "platform": platform.format(),
    }
    with atomic_write(path) as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


_TAR_MODES = {
    ".tar": "w",
    ".oci.tar": "w",
    ".tar.gz": "w:gz",
    ".tgz": "w:gz",
    ".oci.tar.gz": "w:gz",
    ".tar.bz2": "w:bz2",
    ".tbz2": "w:bz2",
    ".tar.xz": "w:xz",
    ".txz": "w:xz",
    ".oci.tar.xz": "w:xz",
    ".tar.zst": "w:zst",
    ".tar.zstd": "w:zst",
    ".oci.tar.zst": "w:zst",
    ".oci.tar.zstd": "w:zst",
}


def _detect_tar_mode(path: str) -> str:
    low = path.lower()
    # Order matters: try longer suffixes first.
    candidates = sorted(_TAR_MODES.keys(), key=len, reverse=True)
    for ext in candidates:
        if low.endswith(ext):
            return _TAR_MODES[ext]
    return "w"


def write_oci_archive(
    out_path: str,
    results: typing.Sequence["PlatformResult"],
    image_ref: str,
) -> None:
    """Write an OCI image-layout tarball describing every result in *results*.

    One image manifest and one image config blob per result, and one `index.json`
    whose descriptors name the platform each was built for, in the order the
    results were asked for. The layer blobs are expected to live in
    LAYER_CACHE_DIR under their standard digest-named filenames (the build engine
    writes them there); this function copies the blob bytes into the archive, once
    per digest, so two platforms that produced the same bytes name one blob.

    A Docker-legacy `manifest.json` is also written at the archive root, for the
    reason and with the one-platform limit the module docstring gives.

    The archive is packed into the descriptor `atomic_write` staged rather than
    into a second open of the temporary's name. The name is one this program
    chose, but the directory it stands in is the user's (`--output /tmp/img.tar`
    stages the temporary in a world-writable directory, where readdir names it
    for anyone sharing it), and between the create and a reopen it can be
    unlinked and replaced with a symlink, which the rename then publishes over
    whatever it pointed at.
    """
    if not results:
        raise RuntimeError("No platform result to package; cannot write OCI archive.")

    mode = _detect_tar_mode(out_path)
    documents: dict[str, bytes] = {}
    layer_blobs: dict[str, str] = {}
    descriptors: list[dict[str, typing.Any]] = []
    docker_manifest: list[dict[str, typing.Any]] = []

    for position, result in enumerate(results):
        _check_config_platform(result.platform, result.image_config)
        manifest, config_bytes, config_digest_hex = _consistent_manifest(result)
        manifest_bytes = canonical_json(manifest)
        manifest_digest_hex = hashlib.sha256(manifest_bytes).hexdigest()
        documents[f"blobs/sha256/{manifest_digest_hex}"] = manifest_bytes
        documents[f"blobs/sha256/{config_digest_hex}"] = config_bytes
        for layer in manifest["layers"]:
            hex_digest = layer["digest"].split(":", 1)[1]
            src = layer_cache_path(layer["digest"])
            if not os.path.isfile(src):
                raise RuntimeError(
                    f"Layer blob {layer['digest']} is missing from the cache; cannot package OCI archive."
                )
            layer_blobs[f"blobs/sha256/{hex_digest}"] = src
        descriptors.append(
            {
                "mediaType": OCI_MANIFEST_MEDIA,
                "digest": "sha256:" + manifest_digest_hex,
                "size": len(manifest_bytes),
                "platform": _index_platform(result.platform),
                "annotations": {
                    "org.opencontainers.image.ref.name": image_ref,
                },
            }
        )
        # The legacy format holds one image, and the first platform asked for is
        # the one a caller stated a preference for.
        if position == 0:
            docker_manifest = _build_docker_manifest(manifest, config_digest_hex, image_ref)

    index = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX_MEDIA,
        "manifests": descriptors,
    }
    index_bytes = canonical_json(index)
    oci_layout_bytes = canonical_json({"imageLayoutVersion": "1.0.0"})
    docker_manifest_bytes = canonical_json(docker_manifest)

    out_abs = os.path.abspath(out_path)
    with (
        atomic_write(out_abs, binary=True) as tmp_fh,
        tarfile.open(fileobj=tmp_fh, mode=mode) as tf,  # type: ignore[call-overload]
    ):
        # oci-layout first so our own install probe detects the
        # OCI format on the first member it sees.
        _add_bytes(tf, "oci-layout", oci_layout_bytes)
        _add_bytes(tf, "index.json", index_bytes)
        _add_bytes(tf, "manifest.json", docker_manifest_bytes)
        for arcname, document in sorted(documents.items()):
            _add_bytes(tf, arcname, document)
        for arcname, src in sorted(layer_blobs.items()):
            _add_file(tf, src, arcname)


def _consistent_manifest(result: "PlatformResult") -> tuple[dict[str, typing.Any], bytes, str]:
    """Return (manifest, config bytes, config digest hex) that agree with each other.

    A manifest whose config descriptor does not address the config bytes about to
    be written is corrected here, since that digest is what a consumer verifies
    the blob it reads against. The result is left alone: it is the caller's, and a
    second output would correct it again.
    """
    config_bytes = canonical_json(result.image_config)
    config_digest_hex = hashlib.sha256(config_bytes).hexdigest()
    manifest = result.manifest
    if manifest["config"]["digest"] != "sha256:" + config_digest_hex:
        manifest = dict(manifest)
        manifest["config"] = dict(manifest["config"])
        manifest["config"]["digest"] = "sha256:" + config_digest_hex
        manifest["config"]["size"] = len(config_bytes)
    return manifest, config_bytes, config_digest_hex


def _index_platform(platform: Platform) -> dict[str, str]:
    """The `platform` object of an index descriptor: a variant only where there is one."""
    field = {"architecture": platform.architecture, "os": platform.os}
    if platform.variant:
        field["variant"] = platform.variant
    return field


def _check_config_platform(platform: Platform, image_config: dict[str, typing.Any]) -> None:
    """Refuse an image config that answers for a platform other than *platform*.

    The descriptor written for it says what its manifest is for, and that is what
    a registry matches a puller against, so a config disagreeing with it hands the
    wrong image to whoever asked for this platform. Only what the config states is
    compared: a field it leaves out claims nothing.
    """
    for field, expected in (
        ("os", platform.os),
        ("architecture", platform.architecture),
        ("variant", platform.variant),
    ):
        declared = image_config.get(field, expected)
        if declared != expected:
            raise RuntimeError(
                f"Image config declares {field} '{declared}', not the '{platform}' its "
                f"descriptor describes; cannot package OCI archive."
            )


def _build_docker_manifest(
    manifest: dict[str, typing.Any],
    config_digest_hex: str,
    image_ref: str,
) -> list[dict[str, typing.Any]]:
    """Build the Docker-legacy `manifest.json` content for one image.

    Used by `docker load` to find the image's config blob and ordered
    layer list inside the archive. Paths are tarball-relative. The format has no
    platform of its own and no way to name a second image for the same tag, which
    is why one platform's manifest reaches it and the others do not.
    """
    layer_paths = []
    layer_sources = {}
    for layer in manifest.get("layers", []):
        digest = layer["digest"]
        hex_digest = digest.split(":", 1)[1]
        layer_paths.append(f"blobs/sha256/{hex_digest}")
        layer_sources[digest] = {
            "mediaType": layer.get("mediaType", OCI_LAYER_MEDIA),
            "size": layer["size"],
            "digest": digest,
        }
    entry: dict[str, typing.Any] = {
        "Config": f"blobs/sha256/{config_digest_hex}",
        "RepoTags": [image_ref] if image_ref else [],
        "Layers": layer_paths,
    }
    if layer_sources:
        entry["LayerSources"] = layer_sources
    return [entry]


def _add_bytes(tf: tarfile.TarFile, arcname: str, data: bytes) -> None:
    import io

    tinfo = tarfile.TarInfo(arcname)
    tinfo.size = len(data)
    tinfo.mode = 0o644
    tinfo.mtime = 0
    tinfo.uid = 0
    tinfo.gid = 0
    tinfo.uname = ""
    tinfo.gname = ""
    tf.addfile(tinfo, io.BytesIO(data))


def _add_file(tf: tarfile.TarFile, src_path: str, arcname: str) -> None:
    st = os.stat(src_path)
    tinfo = tarfile.TarInfo(arcname)
    tinfo.size = st.st_size
    tinfo.mode = 0o644
    tinfo.mtime = 0
    tinfo.uid = 0
    tinfo.gid = 0
    tinfo.uname = ""
    tinfo.gname = ""
    with open(src_path, "rb") as fh:
        tf.addfile(tinfo, fh)
