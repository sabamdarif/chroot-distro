# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Resolve an image reference to one platform's manifest, then fill the rootfs.

`pull_image` is the whole entry point. It answers from the manifest cache when it can,
authenticates and fetches when it cannot, downloads every missing layer in parallel,
then applies them in order into a rootfs the caller has already validated. The platform
it is given is the whole platform, which is what picks a manifest out of an index and
what addresses the manifest cache.

The rootfs arrives as a *descriptor*, not a path. `install` walks
`containers/<name>/rootfs` with O_NOFOLLOW and hands the result straight down, so no
name between that check and the last tar member written is resolved a second time.

The Accept header asks for all four manifest types. An index or manifest list is narrowed by
`_pick_platform`: os must be linux, architecture must match, and a variant matches
either exactly or when the entry declares none. A miss falls back to any linux entry
for the architecture, and only then fails, listing what the image does offer, since
"no image for aarch64" is unhelpful without that. The `Content-Type` header wins over
the body's own `mediaType` for deciding which shape arrived, kept as `_ct` on the
parsed dict, and the digest of the bytes that arrived is kept beside it as `_digest`,
which is what a build records as the base image it resolved to. Both are private keys
a caller strips before a manifest goes back to a registry (`push._strip_private_keys`).
Selected child manifests and config blobs must match the descriptor size and SHA-256
digest over the received bytes. Both documents must pass before the cache is updated.

Layer order is the one thing that cannot be relaxed. Downloads run in parallel across
`layer_download_workers()`, but application is strictly sequential, because a later
layer's whiteouts and overwrites only mean anything against the tree the earlier ones
built.

Failures are translated where the HTTP status is known and left alone otherwise: 401
and 403 become the credential message, 404 becomes "does not exist", and a cache miss
that then fails to reach the network says how many layers were missing, so a user can
tell an offline problem from a wrong reference. A failed config fetch stops the pull.
"""

import contextlib
import hashlib
import json
import os
import re
import signal
import threading
import typing
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from chroot_distro.arch import Platform
from chroot_distro.constants import layer_download_workers
from chroot_distro.helpers.docker.cache import (
    all_layers_cached,
    layer_cache_path,
    load_manifest_cache,
    save_manifest_cache,
)
from chroot_distro.helpers.docker.layers import apply_layer, download_blob
from chroot_distro.helpers.docker.media import (
    DOCKER_MANIFEST_LIST_MEDIA,
    DOCKER_MANIFEST_MEDIA,
    OCI_INDEX_MEDIA,
    OCI_MANIFEST_MEDIA,
)
from chroot_distro.helpers.docker.refs import parse_image_ref, parse_reference
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_denied_msg,
    auth_note,
    get_auth_token,
    insecure_for,
    opener,
    rate_limited_msg,
    registry_base_url,
)
from chroot_distro.helpers.download import (
    MAX_METADATA_BYTES,
    NETWORK_ERRORS,
    _LiveResponses,
    declared_length,
    new_request,
    require_complete_body,
    retry_http,
)
from chroot_distro.message import log_error, log_info
from chroot_distro.progress import AggregateByteProgress, fmt_size

_MANIFEST_LIST_TYPES = frozenset(
    {
        DOCKER_MANIFEST_LIST_MEDIA,
        OCI_INDEX_MEDIA,
    }
)

_ACCEPT_HEADER = ", ".join(
    [
        OCI_INDEX_MEDIA,
        DOCKER_MANIFEST_LIST_MEDIA,
        OCI_MANIFEST_MEDIA,
        DOCKER_MANIFEST_MEDIA,
    ]
)


def _layer_short_id(digest: str) -> str:
    return digest.rsplit(":", maxsplit=1)[-1][:12]


def _check_layer_media_type(layer: dict[str, typing.Any], layer_index: int, n_layers: int) -> None:
    pass


def _download_layers_parallel(
    repo: str,
    layers: list[dict[str, typing.Any]],
    auth: str,
    base: str,
    image_ref: str,
    insecure: bool = False,
) -> None:
    """Download uncached layers, using a thread pool when more than one is missing."""
    n_layers = len(layers)
    pending: list[tuple[int, dict[str, typing.Any]]] = []

    for i, layer in enumerate(layers):
        _check_layer_media_type(layer, i, n_layers)
        digest = layer["digest"]
        short_id = _layer_short_id(digest)
        if os.path.isfile(layer_cache_path(digest)):
            log_info(f"{short_id}: Layer {i + 1}/{n_layers} already cached, skipping download.")
        else:
            pending.append((i, layer))

    if not pending:
        return

    parallel = len(pending) > 1
    total_bytes = sum(layer.get("size", 0) or 0 for _, layer in pending) if parallel else 0
    aggregate = AggregateByteProgress(total_bytes, label="layers") if parallel else None
    abort_event = threading.Event()
    # Shared registry of in-flight HTTP responses. On SIGINT we force-close
    # every live socket so worker threads blocked in resp.read() unblock
    # immediately, rather than hanging until the socket timeout expires.
    live_responses = _LiveResponses(lock=threading.Lock(), responses=set())

    workers_limit = layer_download_workers()
    # When a single layer is pending, give it every worker as segment
    # connections. With several pending layers, split the workers between
    # concurrent layers so the total connection count stays near the budget
    # instead of multiplying workers_limit by the number of layers.
    connections_per_layer = (
        workers_limit if len(pending) == 1 else max(1, workers_limit // min(len(pending), workers_limit))
    )

    def _download_one(item: tuple[int, dict[str, typing.Any]]) -> None:
        i, layer = item
        digest = layer["digest"]
        short_id = _layer_short_id(digest)
        size = layer.get("size", 0)
        size_str = f" ({fmt_size(size)})" if size else ""
        log_info(f"{short_id}: Downloading layer {i + 1}/{n_layers}{size_str}...")
        try:
            download_blob(
                repo,
                digest,
                auth,
                base=base,
                byte_progress=aggregate,
                abort_event=abort_event,
                live_responses=live_responses,
                connections=connections_per_layer,
                insecure=insecure,
            )
        except urllib.error.HTTPError as dl_err:
            if dl_err.code in (401, 403):
                raise RuntimeError(auth_denied_msg(image_ref, dl_err.code)) from dl_err
            if dl_err.code == 429:
                raise RuntimeError(rate_limited_msg(image_ref, parse_image_ref(image_ref), dl_err)) from dl_err
            raise
        except NETWORK_ERRORS as dl_err:
            raise RuntimeError(f"Network error downloading layer {i + 1}/{n_layers} ({short_id}): {dl_err}") from dl_err

    def _on_sigint(_signum, _frame):
        abort_event.set()
        live_responses.close_all()
        raise KeyboardInterrupt

    prev_sigint = signal.getsignal(signal.SIGINT)
    # signal.signal only works on the main thread; suppress if we're not on it.
    with contextlib.suppress(ValueError):
        signal.signal(signal.SIGINT, _on_sigint)
    try:
        if len(pending) == 1:
            _download_one(pending[0])
            return

        workers = min(workers_limit, len(pending))
        log_info(f"Downloading {len(pending)} layer(s) with {workers} workers...")
        executor = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {executor.submit(_download_one, item): item for item in pending}
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            abort_event.set()
            live_responses.close_all()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        except Exception:
            abort_event.set()
            live_responses.close_all()
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
    finally:
        with contextlib.suppress(ValueError):
            signal.signal(signal.SIGINT, prev_sigint)
        if aggregate is not None:
            aggregate.clear()


def _read_descriptor(
    descriptor: object, label: str, *, max_size: int = MAX_METADATA_BYTES, default_size: int | None = None
) -> tuple[str, int]:
    if not isinstance(descriptor, dict):
        raise RuntimeError(f"{label} descriptor must be an object.")
    digest = descriptor.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RuntimeError(f"{label} descriptor must have a lowercase SHA-256 digest.")
    size = descriptor.get("size", default_size)
    if type(size) is not int or not 0 <= size <= max_size:
        raise RuntimeError(f"{label} descriptor has an invalid size.")
    return digest, size


def _fetch_metadata(
    req: urllib.request.Request, label: str, insecure: bool, expected: tuple[str, int] | None = None
) -> tuple[dict[str, typing.Any], str, str]:

    def _attempt():
        with opener(insecure).open(req) as resp:
            body = resp.read(MAX_METADATA_BYTES + 1)
            declared = declared_length(resp)
            content_type = resp.headers.get("Content-Type", "")
        if len(body) > MAX_METADATA_BYTES:
            raise RuntimeError(f"{label} is larger than {MAX_METADATA_BYTES} bytes.")
        require_complete_body(len(body), declared, label)
        return body, content_type

    body, content_type = typing.cast(tuple[bytes, str], retry_http(_attempt, what=f"Fetching {label}"))
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if expected is not None:
        expected_digest, expected_size = expected
        if len(body) != expected_size:
            raise RuntimeError(f"{label} size mismatch (expected {expected_size}, got {len(body)} bytes).")
        if digest != expected_digest:
            raise RuntimeError(f"{label} digest mismatch (expected {expected_digest}).")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise RuntimeError(f"{label} is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} must be a JSON object.")
    return data, content_type, digest


def _get_manifest(
    repo: str, ref: str, auth: str, base: str, insecure: bool = False, *, expected_size: int | None = None
) -> dict[str, typing.Any]:
    url = f"{base}/v2/{repo}/manifests/{ref}"
    headers = {**_ua(), "Accept": _ACCEPT_HEADER}
    if auth:
        headers["Authorization"] = auth
    req = new_request(url, headers=headers)
    expected = (ref, expected_size) if expected_size is not None else None
    label = "Child manifest" if expected is not None else "Manifest"
    data, content_type, digest = _fetch_metadata(req, label, insecure, expected)
    media_type = content_type.split(";")[0].strip() or data.get("mediaType", "")
    if not isinstance(media_type, str):
        raise RuntimeError(f"{label} mediaType must be a string.")
    data["_ct"] = media_type
    data["_digest"] = digest
    return data


def _pick_platform(
    entries: object, arch: str, variant: str, image_ref: str
) -> dict[str, typing.Any]:
    """Find the manifest list entry matching arch (and optionally variant)."""
    if not isinstance(entries, list):
        raise RuntimeError("Manifest index field 'manifests' must be a list.")
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Manifest index entries must be objects.")
        plat = entry.get("platform", {})
        if not isinstance(plat, dict) or any(
            key in plat and not isinstance(plat[key], str) for key in ("os", "architecture", "variant")
        ):
            raise RuntimeError("Manifest index platform must be an object with string fields.")
    descriptors = typing.cast(list[dict[str, typing.Any]], entries)
    for entry in descriptors:
        plat = entry.get("platform", {})
        if plat.get("os", "linux") != "linux":
            continue
        if plat.get("architecture") != arch:
            continue
        if variant and plat.get("variant", "") not in (variant, ""):
            continue
        return entry

    # Fallback: any linux entry for the arch, whatever its variant.
    for entry in descriptors:
        plat = entry.get("platform", {})
        if plat.get("os", "linux") == "linux" and plat.get("architecture") == arch:
            return entry

    available = []
    for e in descriptors:
        plat = e.get("platform", {})
        if plat.get("os", "linux") != "linux":
            continue
        a = plat.get("architecture", "?")
        v = plat.get("variant", "")
        available.append(f"{a}/{v}" if v else a)
    raise RuntimeError(
        f"No image found for architecture '{arch}' in '{image_ref}'. "
        f"Available Linux platforms: {', '.join(available) or 'none'}"
    )


def _resolve_single_manifest(
    image_ref: str, platform: Platform, insecure: bool = False
) -> tuple[dict[str, typing.Any], str, str, str]:
    """Return (single_image_manifest, auth, repo, base) for the platform."""
    parsed = parse_reference(image_ref)
    registry, repo, tag = parsed.registry, parsed.repo, parsed.manifest_ref

    log_info(f"Authenticating with registry{auth_note()}...")
    auth, base = get_auth_token(repo, registry, insecure=insecure)

    log_info(f"Fetching manifest for '{image_ref}'...")
    manifest = _get_manifest(repo, tag, auth, base, insecure=insecure)

    if manifest["_ct"] in _MANIFEST_LIST_TYPES or "manifests" in manifest:
        target = _pick_platform(
            manifest.get("manifests"),
            platform.architecture,
            platform.variant,
            image_ref,
        )
        digest, size = _read_descriptor(target, "Child manifest")
        log_info(f"Fetching {platform} manifest...")
        manifest = _get_manifest(repo, digest, auth, base, insecure=insecure, expected_size=size)

    return manifest, auth, repo, base


def _fetch_config_blob(
    repo: str, descriptor: object, auth: str, base: str, insecure: bool = False
) -> dict[str, typing.Any]:
    """Fetch and verify the config named by an image manifest."""
    digest, size = _read_descriptor(descriptor, "Image config")
    headers = _ua()
    if auth:
        headers["Authorization"] = auth
    req = new_request(f"{base}/v2/{repo}/blobs/{digest}", headers=headers)
    config, _, _ = _fetch_metadata(req, "Image config", insecure, (digest, size))
    if "architecture" in config and not isinstance(config["architecture"], str):
        raise RuntimeError("Image config architecture must be a string.")
    if config.get("config") is not None and not isinstance(config["config"], dict):
        raise RuntimeError("Image config field 'config' must be an object or null.")
    return config


def pull_image(image_ref: str, rootfs_fd: int, platform: Platform, insecure: bool = False) -> dict[str, typing.Any]:
    """Pull an OCI/Docker image and extract all layers into the *rootfs_fd* tree.

    The rootfs is a **descriptor**, not a path: `install` validates
    containers/<name>/rootfs with an O_NOFOLLOW walk and hands the result
    straight down, so nothing between that check and the last member written
    resolves the name a second time.

    *platform* is the whole platform, not an architecture: it picks the manifest
    out of an index and it addresses the manifest cache, so an `arm` variant is a
    cache entry of its own rather than one shared with every other `arm`.

    The manifest is checked in the local cache first.
    """
    auth = ""
    base = None

    # The grammar again, since build's FROM and COPY --from reach here with a
    # Dockerfile's text, and a digest is a pin this program cannot verify, so it
    # does not pull by one.
    parsed = parse_reference(image_ref)
    if parsed.digest:
        raise RuntimeError("pulling an image by digest is not supported; use a tag")
    registry, repo = parsed.registry, parsed.repo
    ref = (parsed.registry, parsed.repo, parsed.tag)
    manifest, _cached_repo, image_config = load_manifest_cache(image_ref, platform)
    cache_miss = manifest is None
    # Docker Hub is verified HTTPS whatever --allow-insecure says; decided
    # here, once, so no request below can use the insecure opener for it.
    insecure = insecure_for(registry, insecure)

    if manifest is not None:
        layers = manifest.get("layers", [])
        if all_layers_cached(layers):
            log_info(f"Image '{image_ref}' ({platform}) is cached.")
        else:
            missing = sum(1 for layer in layers if not os.path.isfile(layer_cache_path(layer["digest"])))
            log_info(f"Downloading {missing} missing layer(s) for '{image_ref}' ({platform})...")
            try:
                log_info(f"Authenticating with registry{auth_note()}...")
                auth, base = get_auth_token(repo, registry, insecure=insecure)
            except NETWORK_ERRORS as net_err:
                if isinstance(net_err, urllib.error.HTTPError):
                    if net_err.code in (401, 403):
                        raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                    if net_err.code == 429:
                        raise RuntimeError(rate_limited_msg(image_ref, ref, net_err)) from net_err
                    if net_err.code == 404:
                        raise RuntimeError(
                            f"Image not found: '{image_ref}' does not exist on the registry."
                        ) from net_err
                log_error(
                    f"{missing} of {len(layers)} layer(s) for '{image_ref}' ({platform}) are not in the local cache."
                )
                raise RuntimeError(f"Network error: {net_err}") from net_err
    else:
        try:
            manifest, auth, repo, base = _resolve_single_manifest(image_ref, platform, insecure=insecure)
        except NETWORK_ERRORS as net_err:
            if isinstance(net_err, urllib.error.HTTPError):
                if net_err.code in (401, 403):
                    raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                if net_err.code == 429:
                    raise RuntimeError(rate_limited_msg(image_ref, ref, net_err)) from net_err
                if net_err.code == 404:
                    raise RuntimeError(f"Image not found: '{image_ref}' does not exist on the registry.") from net_err
            log_error(f"No cached manifest found for '{image_ref}' ({platform}).")
            raise RuntimeError(f"Network error: {net_err}") from net_err
    layers = manifest.get("layers", [])
    if not isinstance(layers, list):
        raise RuntimeError("Manifest field 'layers' must be a list.")
    if not layers:
        raise RuntimeError(f"Manifest for '{image_ref}' contains no filesystem layers.")

    if base is None:
        base = registry_base_url(registry, insecure=insecure)

    if cache_miss:
        for layer in layers:
            _read_descriptor(layer, "Layer", max_size=2**63 - 1, default_size=0)
        try:
            image_config = _fetch_config_blob(repo, manifest.get("config"), auth, base, insecure=insecure)
        except NETWORK_ERRORS as net_err:
            if isinstance(net_err, urllib.error.HTTPError):
                if net_err.code in (401, 403):
                    raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                if net_err.code == 429:
                    raise RuntimeError(rate_limited_msg(image_ref, ref, net_err)) from net_err
            raise RuntimeError(f"Could not fetch image config for '{image_ref}': {net_err}") from net_err
        save_manifest_cache(image_ref, platform, manifest, repo, image_config)

    n_layers = len(layers)
    _download_layers_parallel(repo, layers, auth, base, image_ref, insecure=insecure)

    for i, layer in enumerate(layers):
        digest = layer["digest"]
        short_id = _layer_short_id(digest)
        layer_path = layer_cache_path(digest)
        log_info(f"{short_id}: Applying layer {i + 1}/{n_layers}...")
        apply_layer(layer_path, rootfs_fd)

    return {
        "manifest": manifest,
        "image_config": image_config,
    }
