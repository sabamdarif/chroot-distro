import hashlib
import os
import urllib.request

from chroot_distro.atomic import atomic_replace
from chroot_distro.helpers.docker.cache import layer_cache_path
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_opener,
    registry_base_url,
)
from chroot_distro.helpers.tar_extract import extract_tar_to_rootfs
from chroot_distro.progress import clear_bar, draw_bytes_bar


def download_blob(
    repo: str, digest: str, token: str, registry: str = "",
) -> str:
    """Download a blob to the layer cache; return the local file path.

    Streams the bytes through sha256 and verifies the result against the
    expected *digest* before promoting the .tmp file.
    """
    dest = layer_cache_path(digest)
    if os.path.isfile(dest):
        return dest

    if ":" not in digest:
        raise RuntimeError(f"Malformed layer digest '{digest}'.")
    algo, expected_hex = digest.split(":", 1)
    if algo.lower() != "sha256":
        raise RuntimeError(
            f"Unsupported layer digest algorithm '{algo}' (only sha256 "
            f"is supported)."
        )

    base = registry_base_url(registry)
    url = f"{base}/v2/{repo}/blobs/{digest}"
    headers = {**_ua()}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    hasher = hashlib.sha256()

    try:
        with atomic_replace(dest) as tmp:
            with auth_opener().open(req) as resp, open(tmp, "wb") as fh:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    draw_bytes_bar(downloaded, total, noun="downloaded")
            actual_hex = hasher.hexdigest()
            if actual_hex != expected_hex.lower():
                raise RuntimeError(
                    f"Layer integrity check failed for digest '{digest}': "
                    f"expected {expected_hex}, got {actual_hex}."
                )
    finally:
        clear_bar()
    return dest


def apply_layer(layer_path: str, rootfs_dir: str) -> None:
    """Apply one OCI/Docker layer (gzipped tar) onto rootfs_dir."""
    extract_tar_to_rootfs(layer_path, rootfs_dir, handle_whiteouts=True)
