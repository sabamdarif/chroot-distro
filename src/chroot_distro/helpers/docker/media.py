# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""OCI and Docker media types, descriptor validation and canonical JSON.

Both manifest formats are accepted on pull, so the strings are needed in pairs. A
digest is taken over the exact bytes, so `canonical_json` (sorted keys, no whitespace)
is what a manifest or config must be serialised with: re-encoding a document any other
way changes its digest and the registry rejects it.
"""

import json
import re
import typing


def canonical_json(obj) -> bytes:
    """Return canonical (sorted-keys, no-whitespace) JSON bytes.

    Used to hash and sign image manifests / configs.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


OCI_MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"

DOCKER_MANIFEST_LIST_MEDIA = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST_MEDIA = "application/vnd.docker.distribution.manifest.v2+json"


def read_descriptor(
    descriptor: object, label: str, *, max_size: int = 2**63 - 1, size_optional: bool = False
) -> tuple[str, int | None]:
    if not isinstance(descriptor, dict):
        raise RuntimeError(f"{label} descriptor must be an object.")
    digest = descriptor.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RuntimeError(f"{label} descriptor must have a lowercase SHA-256 digest.")
    if size_optional and "size" not in descriptor:
        return digest, None
    size = descriptor.get("size")
    if type(size) is not int or not 0 <= size <= max_size:
        raise RuntimeError(f"{label} descriptor has an invalid size.")
    return digest, size


def manifest_layers(
    manifest: object, *, size_optional: bool = False
) -> tuple[list[dict[str, typing.Any]], dict[str, int | None]]:
    """Return all layer positions and one declared size per digest."""
    if not isinstance(manifest, dict):
        raise RuntimeError("Image manifest must be an object.")
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise RuntimeError("Manifest field 'layers' must be a list.")
    sizes: dict[str, int | None] = {}
    for layer in layers:
        digest, size = read_descriptor(layer, "Layer", size_optional=size_optional)
        previous = sizes.setdefault(digest, size)
        if size is None:
            continue
        if previous is not None and size != previous:
            raise RuntimeError(f"Layer descriptors disagree on the size of {digest}.")
        sizes[digest] = size
    return layers, sizes


def normalized_variant(architecture: str, variant: str) -> str:
    return "" if (architecture, variant) in (("arm64", "v8"), ("amd64", "v1")) else variant
