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

The Accept header asks for all four manifest types. Nested indexes can supply
platform fields inherited by their children. The chosen image must match the
requested Linux architecture, with an exact variant preferred over an omitted
one. The `Content-Type` header wins over
the body's own `mediaType` for deciding which shape arrived, kept as `_ct` on the
parsed dict, and the digest of the bytes that arrived is kept beside it as `_digest`,
which is what a build records as the base image it resolved to. Both are private keys
a caller strips before a manifest goes back to a registry (`push._strip_private_keys`).
Selected child manifests and config blobs must match the descriptor size and SHA-256
digest over the received bytes. Both documents must pass before the cache is updated.

Each missing digest gets one download, up to `layer_download_workers()` in
parallel. Every manifest position is applied in order, including repeated layers.

Failures are translated where the HTTP status is known and left alone otherwise: 401
and 403 become the credential message, 404 becomes "does not exist", and a cache miss
that then fails to reach the network says how many layers were missing, so a user can
tell an offline problem from a wrong reference. A failed config fetch stops the pull.
"""

import contextlib
import hashlib
import json
import os
import signal
import threading
import typing
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from chroot_distro.arch import Platform
from chroot_distro.constants import layer_download_workers
from chroot_distro.helpers.docker.cache import (
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
    manifest_layers,
    normalized_variant,
    read_descriptor,
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
    registry_failure,
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
from chroot_distro.message import log_error, log_info, quote_path
from chroot_distro.progress import AggregateByteProgress, fmt_size

_MANIFEST_LIST_TYPES = (DOCKER_MANIFEST_LIST_MEDIA, OCI_INDEX_MEDIA)
_INDEX_ENTRY_TYPES = (*_MANIFEST_LIST_TYPES, OCI_MANIFEST_MEDIA, DOCKER_MANIFEST_MEDIA)
_MAX_INDEX_DEPTH = 16
_MAX_INDEX_FETCHES = 128
_PLATFORM_FIELDS = ("os", "architecture", "variant")

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


def _download_layers_parallel(
    repo: str,
    layers: list[dict[str, typing.Any]],
    sizes: dict[str, int | None],
    auth: str,
    base: str,
    image_ref: str,
    insecure: bool = False,
) -> None:
    """Download uncached layers, using a thread pool when more than one is missing."""
    n_layers = len(layers)
    pending: list[tuple[int, str]] = []
    seen: set[str] = set()

    for i, layer in enumerate(layers):
        digest = layer["digest"]
        if digest in seen:
            continue
        seen.add(digest)
        short_id = _layer_short_id(digest)
        if os.path.isfile(layer_cache_path(digest)):
            log_info(f"{short_id}: Layer {i + 1}/{n_layers} already cached, skipping download.")
        else:
            pending.append((i, digest))

    if not pending:
        return

    parallel = len(pending) > 1
    total_bytes = sum(sizes[digest] or 0 for _, digest in pending) if parallel else 0
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

    def _download_one(item: tuple[int, str]) -> None:
        i, digest = item
        short_id = _layer_short_id(digest)
        size = sizes[digest]
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
                expected_size=size,
            )
        except urllib.error.HTTPError as dl_err:
            if dl_err.code in (401, 403):
                raise RuntimeError(auth_denied_msg(image_ref, dl_err.code)) from dl_err
            if dl_err.code == 429:
                raise RuntimeError(rate_limited_msg(image_ref, parse_image_ref(image_ref), dl_err)) from dl_err
            raise RuntimeError(f"Could not download layer {i + 1}/{n_layers}: {registry_failure(dl_err)}") from dl_err
        except NETWORK_ERRORS as dl_err:
            failure = registry_failure(dl_err)
            raise RuntimeError(f"Network error downloading layer {i + 1}/{n_layers} ({short_id}): {failure}") from dl_err

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


def _index_entries(entries: object) -> list[dict[str, typing.Any]]:
    if not isinstance(entries, list):
        raise RuntimeError("Manifest index field 'manifests' must be a list.")
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Manifest index entries must be objects.")
    return entries


def _platform_fields(data: object, label: str) -> dict[str, str]:
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} must be an object with string fields.")
    for key in _PLATFORM_FIELDS:
        if key in data and not isinstance(data[key], str):
            raise RuntimeError(f"{label} must be an object with string fields (invalid {key}).")
    return {key: data[key] for key in _PLATFORM_FIELDS if data.get(key)}


def _merge_platform(
    inherited: dict[str, str], declared: dict[str, str], platform: Platform, label: str
) -> dict[str, str]:
    fields = inherited | declared
    arch = fields.get("architecture", platform.architecture)
    for key in inherited.keys() & declared.keys():
        old, new = inherited[key], declared[key]
        if key == "variant":
            old, new = normalized_variant(arch, old), normalized_variant(arch, new)
        if old != new:
            raise RuntimeError(f"{label} disagrees with its index platform on {key}.")
    return fields


def _matches_platform(fields: dict[str, str], platform: Platform) -> bool:
    variant = fields.get("variant")
    return (
        fields.get("os", platform.os) == platform.os
        and fields.get("architecture", platform.architecture) == platform.architecture
        and (variant is None or normalized_variant(platform.architecture, variant) == platform.variant)
    )


def _is_index(manifest: dict[str, typing.Any]) -> bool:
    return manifest["_ct"] in _MANIFEST_LIST_TYPES or "manifests" in manifest


class _Image(typing.NamedTuple):
    manifest: dict[str, typing.Any]
    config: dict[str, typing.Any]
    layers: list[dict[str, typing.Any]]
    sizes: dict[str, int | None]


def _resolve_image(image_ref: str, platform: Platform, insecure: bool = False) -> tuple[_Image, str, str]:
    """Resolve and verify the selected manifest and config."""
    parsed = parse_reference(image_ref)
    registry, repo, tag = parsed.registry, parsed.repo, parsed.manifest_ref

    log_info(f"Authenticating with registry{auth_note()}...")
    auth, base = get_auth_token(repo, registry, insecure=insecure)

    def _read_image(manifest: dict[str, typing.Any]) -> _Image:
        layers, sizes = manifest_layers(manifest, size_optional=True)
        try:
            config = _fetch_config_blob(repo, manifest.get("config"), auth, base, insecure=insecure)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RuntimeError(auth_denied_msg(image_ref, exc.code)) from exc
            if exc.code == 429:
                ref = (registry, repo, tag)
                raise RuntimeError(rate_limited_msg(image_ref, ref, exc)) from exc
            raise RuntimeError(f"Could not fetch image config for '{image_ref}': {registry_failure(exc)}") from exc
        except NETWORK_ERRORS as exc:
            raise RuntimeError(f"Could not fetch image config for '{image_ref}': {registry_failure(exc)}") from exc
        return _Image(manifest, config, layers, sizes)

    log_info(f"Fetching manifest for '{image_ref}'...")
    manifest = _get_manifest(repo, tag, auth, base, insecure=insecure)
    if manifest.get("artifactType"):
        raise RuntimeError(f"'{image_ref}' is an artifact rather than an image.")
    if not _is_index(manifest):
        image = _read_image(manifest)
        if not _matches_platform(_platform_fields(image.config, "Image config"), platform):
            raise RuntimeError(f"Image config does not match the requested platform '{platform}'.")
        return image, auth, base

    seen: set[tuple[str, int, tuple[tuple[str, str], ...]]] = set()
    available: dict[str, None] = {}

    def _candidates(
        index: dict[str, typing.Any], inherited: dict[str, str], depth: int
    ) -> typing.Iterator[tuple[_Image, dict[str, str]]]:
        if depth >= _MAX_INDEX_DEPTH:
            raise RuntimeError("Registry image index nesting is too deep.")
        candidates = []
        for entry in _index_entries(index.get("manifests")):
            media = entry.get("mediaType")
            if entry.get("artifactType") or (media is not None and media not in _INDEX_ENTRY_TYPES):
                continue
            declared = _platform_fields(entry.get("platform", {}), "Manifest index platform")
            fields = _merge_platform(inherited, declared, platform, "Nested descriptor")
            arch, variant = fields.get("architecture"), fields.get("variant")
            if arch and fields.get("os", "linux") == "linux" and len(available) < 20:
                available.setdefault(f"{arch}/{variant}" if variant else arch, None)
            if _matches_platform(fields, platform):
                candidates.append((entry, fields, media))
        if platform.variant:
            candidates.sort(key=lambda candidate: "variant" not in candidate[1])

        for entry, fields, media in candidates:
            digest, size = read_descriptor(entry, "Child manifest", max_size=MAX_METADATA_BYTES)
            assert size is not None
            key = (digest, size, tuple(sorted(fields.items())))
            if key in seen:
                continue
            if len(seen) >= _MAX_INDEX_FETCHES:
                raise RuntimeError("Registry image index contains too many candidate manifests.")
            seen.add(key)
            log_info(f"Fetching {platform} manifest...")
            child = _get_manifest(repo, digest, auth, base, insecure=insecure, expected_size=size)
            if child.get("artifactType"):
                continue
            if _is_index(child) or media in _MANIFEST_LIST_TYPES:
                yield from _candidates(child, fields, depth + 1)
                continue
            image = _read_image(child)
            config_fields = _platform_fields(image.config, "Image config")
            resolved = _merge_platform(fields, config_fields, platform, "Image config")
            if resolved.get("architecture") and _matches_platform(resolved, platform):
                yield image, resolved

    fallback = None
    for image, fields in _candidates(manifest, {}, 0):
        if not platform.variant or fields.get("variant"):
            return image, auth, base
        if fallback is None:
            fallback = image
    if fallback is not None:
        return fallback, auth, base
    platforms = ", ".join(quote_path(item) for item in available) or "none"
    raise RuntimeError(
        f"No image found for '{platform}' in '{image_ref}'. Available Linux platforms: {platforms}"
    )


def _fetch_config_blob(
    repo: str, descriptor: object, auth: str, base: str, insecure: bool = False
) -> dict[str, typing.Any]:
    """Fetch and verify the config named by an image manifest."""
    digest, size = read_descriptor(descriptor, "Image config", max_size=MAX_METADATA_BYTES)
    assert size is not None
    headers = _ua()
    if auth:
        headers["Authorization"] = auth
    req = new_request(f"{base}/v2/{repo}/blobs/{digest}", headers=headers)
    config, _, _ = _fetch_metadata(req, "Image config", insecure, (digest, size))
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
    # Docker Hub is verified HTTPS whatever --allow-insecure says; decided
    # here, once, so no request below can use the insecure opener for it.
    insecure = insecure_for(registry, insecure)

    if manifest is not None:
        layers, sizes = manifest_layers(manifest, size_optional=True)
        missing = sum(not os.path.isfile(layer_cache_path(digest)) for digest in sizes)
        if not missing:
            log_info(f"Image '{image_ref}' ({platform}) is cached.")
        else:
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
                    f"{missing} of {len(sizes)} layer blob(s) for '{image_ref}' ({platform}) are not in the local cache."
                )
                raise RuntimeError(f"Network error: {registry_failure(net_err)}") from net_err
    else:
        try:
            image, auth, base = _resolve_image(image_ref, platform, insecure=insecure)
            manifest, image_config, layers, sizes = image
        except NETWORK_ERRORS as net_err:
            if isinstance(net_err, urllib.error.HTTPError):
                if net_err.code in (401, 403):
                    raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                if net_err.code == 429:
                    raise RuntimeError(rate_limited_msg(image_ref, ref, net_err)) from net_err
                if net_err.code == 404:
                    raise RuntimeError(f"Image not found: '{image_ref}' does not exist on the registry.") from net_err
            log_error(f"No cached manifest found for '{image_ref}' ({platform}).")
            raise RuntimeError(f"Network error: {registry_failure(net_err)}") from net_err
        save_manifest_cache(image_ref, platform, manifest, repo, image_config)

    if base is None:
        base = registry_base_url(registry, insecure=insecure)

    n_layers = len(layers)
    _download_layers_parallel(repo, layers, sizes, auth, base, image_ref, insecure=insecure)

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
