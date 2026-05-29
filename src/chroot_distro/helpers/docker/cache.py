import hashlib
import json
import os
import re

from chroot_distro.atomic import atomic_replace
from chroot_distro.constants import LAYER_CACHE_DIR, MANIFEST_CACHE_DIR
from chroot_distro.helpers.docker.refs import parse_image_ref

# OCI digest grammar
_DIGEST_RE = re.compile(
    r"^[A-Za-z0-9]+(?:[+_.\-][A-Za-z0-9]+)*:[A-Fa-f0-9]+$"
)


def validate_digest(digest: str) -> str:
    """Return *digest* unchanged when well-formed; raise otherwise."""
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
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
    image_ref: str, arch: str,
    manifest: dict, repo: str, image_config: dict,
) -> None:
    """Persist a manifest + image-config pair under the canonical cache key."""
    payload = {"manifest": manifest, "repo": repo, "image_config": image_config}
    with atomic_replace(manifest_cache_path(image_ref, arch)) as tmp, open(tmp, "w") as fh:
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


def all_layers_cached(layers: list) -> bool:
    """Return True iff every layer's blob file is already on disk."""
    return all(
        os.path.isfile(layer_cache_path(layer["digest"])) for layer in layers
    )
