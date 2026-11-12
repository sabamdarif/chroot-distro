# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Re-exports for the registry client, so callers import one name, not five modules."""

from chroot_distro.helpers.docker.cache import (
    all_layers_cached,
    is_valid_digest,
    layer_cache_path,
    load_manifest_cache,
    manifest_cache_path,
    referenced_blob_digests,
    save_manifest_cache,
    validate_digest,
)
from chroot_distro.helpers.docker.layers import (
    apply_layer,
    download_blob,
)
from chroot_distro.helpers.docker.pull import pull_image
from chroot_distro.helpers.docker.push import push_image
from chroot_distro.helpers.docker.refs import (
    ARCH_TO_DOCKER,
    DOCKER_TO_ARCH,
    InvalidReferenceError,
    Reference,
    canonical_ref,
    derive_alias,
    is_repository_path,
    parse_image_ref,
    parse_reference,
    parse_tag_reference,
    with_explicit_tag,
)
from chroot_distro.helpers.docker.transport import (
    AuthStrippingRedirectHandler,
    auth_denied_msg,
    auth_note,
    auth_opener,
    credentials_rejected_msg,
    env_basic_auth,
    get_auth_token,
    push_denied_msg,
    registry_base_url,
)

__all__ = (
    "ARCH_TO_DOCKER",
    "DOCKER_TO_ARCH",
    "AuthStrippingRedirectHandler",
    "InvalidReferenceError",
    "Reference",
    "all_layers_cached",
    "apply_layer",
    "auth_denied_msg",
    "auth_note",
    "auth_opener",
    "canonical_ref",
    "credentials_rejected_msg",
    "derive_alias",
    "download_blob",
    "env_basic_auth",
    "get_auth_token",
    "is_repository_path",
    "is_valid_digest",
    "layer_cache_path",
    "load_manifest_cache",
    "manifest_cache_path",
    "parse_image_ref",
    "parse_reference",
    "parse_tag_reference",
    "pull_image",
    "push_denied_msg",
    "push_image",
    "referenced_blob_digests",
    "registry_base_url",
    "save_manifest_cache",
    "validate_digest",
    "with_explicit_tag",
)
