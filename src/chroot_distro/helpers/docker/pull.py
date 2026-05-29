import json
import os
import ssl
import typing
import urllib.error
import urllib.request

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
    auth_opener,
    get_auth_token,
    registry_base_url,
)
from chroot_distro.message import log_error, log_info
from chroot_distro.progress import fmt_size

_MANIFEST_LIST_TYPES = frozenset({
    DOCKER_MANIFEST_LIST_MEDIA, OCI_INDEX_MEDIA,
})

_ACCEPT_HEADER = ", ".join([
    OCI_INDEX_MEDIA,
    DOCKER_MANIFEST_LIST_MEDIA,
    OCI_MANIFEST_MEDIA,
    DOCKER_MANIFEST_MEDIA,
])


def _get_manifest(
    repo: str, ref: str, token: str, registry: str = ""
) -> dict[str, typing.Any]:
    base = registry_base_url(registry)
    url = f"{base}/v2/{repo}/manifests/{ref}"
    headers = {**_ua(), "Accept": _ACCEPT_HEADER}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        body = resp.read()
        ct = resp.headers.get("Content-Type", "")
    data: dict[str, typing.Any] = json.loads(body)
    data["_ct"] = ct.split(";")[0].strip() or data.get("mediaType", "")
    return data


def _pick_platform(
    entries: list[dict[str, typing.Any]], arch: str, variant: str, image_ref: str
) -> dict[str, typing.Any]:
    """Find the manifest list entry matching arch (and optionally variant)."""
    # Exact match first (arch + non-empty variant must match).
    for entry in entries:
        plat = entry.get("platform", {})
        if plat.get("os", "linux") != "linux":
            continue
        if plat.get("architecture") != arch:
            continue
        if variant and plat.get("variant", "") not in (variant, ""):
            continue
        return entry

    # Variant-agnostic fallback.
    for entry in entries:
        plat = entry.get("platform", {})
        if (plat.get("os", "linux") == "linux"
                and plat.get("architecture") == arch):
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


def _resolve_single_manifest(image_ref: str, arch: str) -> tuple[dict[str, typing.Any], str, str, str]:
    """Return (single_image_manifest, token, repo, registry) for the arch."""
    registry, repo, tag = parse_image_ref(image_ref)

    log_info(f"Authenticating with registry{auth_note()}...")
    token = get_auth_token(repo, registry)

    log_info(f"Fetching manifest for '{image_ref}'...")
    manifest = _get_manifest(repo, tag, token, registry)

    if manifest["_ct"] in _MANIFEST_LIST_TYPES or "manifests" in manifest:
        docker_arch, docker_variant = ARCH_TO_DOCKER.get(arch, (arch, ""))
        target = _pick_platform(
            manifest.get("manifests", []),
            docker_arch,
            docker_variant,
            image_ref,
        )
        log_info(f"Fetching {arch} manifest...")
        manifest = _get_manifest(repo, target["digest"], token, registry)

    return manifest, token, repo, registry


def _fetch_config_blob(
    repo: str, cfg_digest: str, token: str, registry: str = ""
) -> dict[str, typing.Any]:
    """Fetch the image config blob; return parsed dict (empty on error)."""
    if not cfg_digest:
        return {}
    try:
        base = registry_base_url(registry)
        url = f"{base}/v2/{repo}/blobs/{cfg_digest}"
        headers = {**_ua()}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        with auth_opener().open(req) as resp:
            result: dict[str, typing.Any] = json.loads(resp.read())
            return result
    except Exception:
        return {}


def pull_image(image_ref: str, rootfs_dir: str, arch: str) -> dict[str, typing.Any]:
    """Pull an OCI/Docker image and extract all layers into *rootfs_dir*.

    The manifest is checked in the local cache first.
    """
    token = None

    manifest, repo, image_config = load_manifest_cache(image_ref, arch)
    registry = parse_image_ref(image_ref)[0]

    if manifest is not None:
        layers = manifest.get("layers", [])
        if all_layers_cached(layers):
            log_info(f"Image '{image_ref}' ({arch}) is cached.")
        else:
            missing = sum(
                1 for layer in layers
                if not os.path.isfile(layer_cache_path(layer["digest"]))
            )
            log_info(f"Downloading {missing} missing "
                     f"layer(s) for '{image_ref}' ({arch})...")
            try:
                log_info(f"Authenticating with registry{auth_note()}...")
                token = get_auth_token(repo, registry)
            except (urllib.error.URLError, OSError) as net_err:
                if isinstance(net_err, urllib.error.HTTPError):
                    if net_err.code in (401, 403):
                        raise RuntimeError(
                            auth_denied_msg(image_ref, net_err.code)
                        ) from net_err
                    if net_err.code == 404:
                        raise RuntimeError(
                            f"Image not found: '{image_ref}' does not "
                            f"exist on the registry."
                        ) from net_err
                log_error(f"{missing} of {len(layers)} layer(s) for "
                          f"'{image_ref}' ({arch}) are not in the local "
                          f"cache.")
                raise RuntimeError(f"Network error: {net_err}") from net_err
    else:
        try:
            manifest, token, repo, registry = _resolve_single_manifest(
                image_ref, arch
            )
        except (urllib.error.URLError, OSError) as net_err:
            if isinstance(net_err, urllib.error.HTTPError):
                if net_err.code in (401, 403):
                    raise RuntimeError(
                        auth_denied_msg(image_ref, net_err.code)
                    ) from net_err
                if net_err.code == 404:
                    raise RuntimeError(
                        f"Image not found: '{image_ref}' does not exist "
                        f"on the registry."
                    ) from net_err
            log_error(f"No cached manifest found for '{image_ref}' ({arch}).")
            raise RuntimeError(f"Network error: {net_err}") from net_err
        cfg_digest = manifest.get("config", {}).get("digest", "")
        image_config = _fetch_config_blob(repo, cfg_digest, token, registry)
        save_manifest_cache(image_ref, arch, manifest, repo, image_config)

    layers = manifest.get("layers", [])
    if not layers:
        raise RuntimeError(
            f"Manifest for '{image_ref}' contains no filesystem layers."
        )

    n_layers = len(layers)
    for i, layer in enumerate(layers):
        digest = layer["digest"]
        media_type = layer.get("mediaType", "")
        if "zstd" in media_type:
            raise RuntimeError(
                f"Layer {i + 1}/{n_layers} uses zstd compression which is "
                "not supported by Python's tarfile module. "
                "Try a different image tag that ships gzip-compressed layers."
            )

        short_id = digest.split(":")[-1][:12]
        cached_path = layer_cache_path(digest)
        if os.path.isfile(cached_path):
            log_info(f"{short_id}: Layer {i + 1}/{n_layers} already cached, "
                     f"skipping download.")
            layer_path = cached_path
        else:
            size = layer.get("size", 0)
            size_str = f" ({fmt_size(size)})" if size else ""
            log_info(f"{short_id}: Downloading layer "
                     f"{i + 1}/{n_layers}{size_str}...")
            try:
                layer_path = download_blob(repo, digest, token or "", registry)
            except urllib.error.HTTPError as dl_err:
                if dl_err.code in (401, 403):
                    raise RuntimeError(
                        auth_denied_msg(image_ref, dl_err.code)
                    ) from dl_err
                raise
            except (ssl.SSLError, ConnectionError, OSError) as dl_err:
                raise RuntimeError(
                    f"Network error downloading layer {i + 1}/{n_layers} "
                    f"({short_id}): {dl_err}"
                ) from dl_err

        log_info(f"{short_id}: Applying layer {i + 1}/{n_layers}...")
        apply_layer(layer_path, rootfs_dir)

    return {
        "manifest": manifest,
        "image_config": image_config,
    }
