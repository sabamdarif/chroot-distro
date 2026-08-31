# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Resolve an image reference to one architecture's manifest, then fill the rootfs.

`pull_image` is the whole entry point. It answers from the manifest cache when it can,
authenticates and fetches when it cannot, downloads every missing layer in parallel,
then applies them in order into a rootfs the caller has already validated.

The rootfs arrives as a *descriptor*, not a path. `install` walks
`containers/<name>/rootfs` with O_NOFOLLOW and hands the result straight down, so no
name between that check and the last tar member written is resolved a second time.

Two documents come back from a registry and neither is trusted. The Accept header asks
for all four manifest types, and an index or manifest list is narrowed by
`_pick_platform`: os must be linux, architecture must match, and a variant matches
either exactly or when the entry declares none. A miss falls back to any linux entry
for the architecture, and only then fails, listing what the image does offer, since
"no image for aarch64" is unhelpful without that. The `Content-Type` header wins over
the body's own `mediaType` for deciding which shape arrived, kept as `_ct` on the
parsed dict, and the digest of the bytes that arrived is kept beside it as `_digest`,
which is what a build records as the base image it resolved to. Both are private keys
a caller strips before a manifest goes back to a registry (`push._strip_private_keys`).

Layer order is the one thing that cannot be relaxed. Downloads run in parallel across
`layer_download_workers()`, but application is strictly sequential, because a later
layer's whiteouts and overwrites only mean anything against the tree the earlier ones
built.

Failures are translated where the HTTP status is known and left alone otherwise: 401
and 403 become the credential message, 404 becomes "does not exist", and a cache miss
that then fails to reach the network says how many layers were missing, so a user can
tell an offline problem from a wrong reference. A config blob that cannot be fetched is
not fatal: it returns empty, since a rootfs without image metadata is still usable.
"""

import contextlib
import hashlib
import json
import os
import signal
import ssl
import threading
import typing
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

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
from chroot_distro.helpers.docker.refs import ARCH_TO_DOCKER, parse_image_ref
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_denied_msg,
    auth_note,
    get_auth_token,
    opener,
    registry_base_url,
)
from chroot_distro.helpers.download import _LiveResponses, retry_http
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
    token: str | None,
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
                token or "",
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
            raise
        except (ssl.SSLError, ConnectionError, OSError) as dl_err:
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


def _get_manifest(repo: str, ref: str, token: str, base: str, insecure: bool = False) -> dict[str, typing.Any]:
    url = f"{base}/v2/{repo}/manifests/{ref}"
    headers = {**_ua(), "Accept": _ACCEPT_HEADER}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)

    def _attempt():
        with opener(insecure).open(req) as resp:
            return resp.read(), resp.headers.get("Content-Type", "")

    body, ct = typing.cast(tuple[bytes, str], retry_http(_attempt, what=f"Fetching manifest {ref}"))
    data: dict[str, typing.Any] = json.loads(body)
    data["_ct"] = ct.split(";")[0].strip() or data.get("mediaType", "")
    # Over the bytes as they arrived, which is what a digest is defined over: a
    # re-serialised document is a different one.
    data["_digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
    return data


def _pick_platform(
    entries: list[dict[str, typing.Any]], arch: str, variant: str, image_ref: str
) -> dict[str, typing.Any]:
    """Find the manifest list entry matching arch (and optionally variant)."""
    for entry in entries:
        plat = entry.get("platform", {})
        if plat.get("os", "linux") != "linux":
            continue
        if plat.get("architecture") != arch:
            continue
        if variant and plat.get("variant", "") not in (variant, ""):
            continue
        return entry

    # Fallback: any linux entry for the arch, whatever its variant.
    for entry in entries:
        plat = entry.get("platform", {})
        if plat.get("os", "linux") == "linux" and plat.get("architecture") == arch:
            return entry

    available = []
    for e in entries:
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
    image_ref: str, arch: str, insecure: bool = False
) -> tuple[dict[str, typing.Any], str, str, str]:
    """Return (single_image_manifest, token, repo, base) for the arch."""
    registry, repo, tag = parse_image_ref(image_ref)

    log_info(f"Authenticating with registry{auth_note()}...")
    token, base = get_auth_token(repo, registry, insecure=insecure)

    log_info(f"Fetching manifest for '{image_ref}'...")
    manifest = _get_manifest(repo, tag, token, base, insecure=insecure)

    if manifest["_ct"] in _MANIFEST_LIST_TYPES or "manifests" in manifest:
        docker_arch, docker_variant = ARCH_TO_DOCKER.get(arch, (arch, ""))
        target = _pick_platform(
            manifest.get("manifests", []),
            docker_arch,
            docker_variant,
            image_ref,
        )
        log_info(f"Fetching {arch} manifest...")
        manifest = _get_manifest(repo, target["digest"], token, base, insecure=insecure)

    return manifest, token, repo, base


def _fetch_config_blob(
    repo: str, cfg_digest: str, token: str, base: str, insecure: bool = False
) -> dict[str, typing.Any]:
    """Fetch the image config blob; return parsed dict (empty on error)."""
    if not cfg_digest:
        return {}
    try:
        url = f"{base}/v2/{repo}/blobs/{cfg_digest}"
        headers = {**_ua()}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)

        def _attempt():
            with opener(insecure).open(req) as resp:
                return resp.read()

        result: dict[str, typing.Any] = json.loads(
            typing.cast(bytes, retry_http(_attempt, what="Fetching image config"))
        )
        return result
    except Exception:
        return {}


def pull_image(image_ref: str, rootfs_fd: int, arch: str, insecure: bool = False) -> dict[str, typing.Any]:
    """Pull an OCI/Docker image and extract all layers into the *rootfs_fd* tree.

    The rootfs is a **descriptor**, not a path: `install` validates
    containers/<name>/rootfs with an O_NOFOLLOW walk and hands the result
    straight down, so nothing between that check and the last member written
    resolves the name a second time.

    The manifest is checked in the local cache first.
    """
    token = None
    base = None

    manifest, repo, image_config = load_manifest_cache(image_ref, arch)
    registry = parse_image_ref(image_ref)[0]

    if manifest is not None:
        assert repo is not None
        layers = manifest.get("layers", [])
        if all_layers_cached(layers):
            log_info(f"Image '{image_ref}' ({arch}) is cached.")
        else:
            missing = sum(1 for layer in layers if not os.path.isfile(layer_cache_path(layer["digest"])))
            log_info(f"Downloading {missing} missing layer(s) for '{image_ref}' ({arch})...")
            try:
                log_info(f"Authenticating with registry{auth_note()}...")
                token, base = get_auth_token(repo, registry, insecure=insecure)
            except (urllib.error.URLError, OSError) as net_err:
                if isinstance(net_err, urllib.error.HTTPError):
                    if net_err.code in (401, 403):
                        raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                    if net_err.code == 404:
                        raise RuntimeError(
                            f"Image not found: '{image_ref}' does not exist on the registry."
                        ) from net_err
                log_error(f"{missing} of {len(layers)} layer(s) for '{image_ref}' ({arch}) are not in the local cache.")
                raise RuntimeError(f"Network error: {net_err}") from net_err
    else:
        try:
            manifest, token, repo, base = _resolve_single_manifest(image_ref, arch, insecure=insecure)
        except (urllib.error.URLError, OSError) as net_err:
            if isinstance(net_err, urllib.error.HTTPError):
                if net_err.code in (401, 403):
                    raise RuntimeError(auth_denied_msg(image_ref, net_err.code)) from net_err
                if net_err.code == 404:
                    raise RuntimeError(f"Image not found: '{image_ref}' does not exist on the registry.") from net_err
            log_error(f"No cached manifest found for '{image_ref}' ({arch}).")
            raise RuntimeError(f"Network error: {net_err}") from net_err
        cfg_digest = manifest.get("config", {}).get("digest", "")
        image_config = _fetch_config_blob(repo, cfg_digest, token, base, insecure=insecure)
        save_manifest_cache(image_ref, arch, manifest, repo, image_config)

    layers = manifest.get("layers", [])
    if not layers:
        raise RuntimeError(f"Manifest for '{image_ref}' contains no filesystem layers.")

    if base is None:
        base = registry_base_url(registry, insecure=insecure)

    n_layers = len(layers)
    _download_layers_parallel(repo, layers, token, base, image_ref, insecure=insecure)

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
