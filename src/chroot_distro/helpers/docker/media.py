# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""OCI and Docker media type strings, plus the canonical JSON both specs hash over.

Both manifest formats are accepted on pull, so the strings are needed in pairs. A
digest is taken over the exact bytes, so `canonical_json` (sorted keys, no whitespace)
is what a manifest or config must be serialised with: re-encoding a document any other
way changes its digest and the registry rejects it.
"""

import json


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
