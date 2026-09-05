# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Upload a built image to a registry: blobs first, manifest last.

`push_image` pushes what `build` already produced. The manifest cache is the source of
truth, so an image can only be pushed under the exact `image_ref` and `arch` it was
built as, and a layer blob missing from the local cache is refused with a rebuild hint
rather than reconstructed.

Ordering is the registry's rule, not a preference: a manifest naming a blob the registry
does not hold is rejected, so every layer and the config go up first and the manifest
last. Each blob is HEAD-checked first, which is how a re-push of a shared base costs
nothing.

The image config is re-serialised with `canonical_json` and its digest compared against
the one the cached manifest claims *before* any upload starts. The registry verifies
those bytes itself, so a corrupt cache is better caught here than after the layers are
sent. `_strip_private_keys` drops the `_ct` key `pull` stashes in a manifest dict, which
is internal bookkeeping and would change the bytes the digest is over.

Two upload shapes, by size against `CD_PUSH_CHUNK_SIZE`. Below it, one PUT. At or above
it, PATCH chunks where the registry's acknowledged `Range` wins over the local offset
and a transient failure resumes from there, so a dropped connection costs one chunk and
not the layer. The upload URL comes back in a `Location` header that registries spell
absolute, root-relative or relative, hence `_resolve_upload_url`.

Only transient failures retry. A 401 or 403 anywhere becomes `push_denied_msg`, which
names whether credentials were supplied, since "denied" means different things with and
without them.
"""

import hashlib
import os
import sys
import time
import typing
import urllib.error
import urllib.parse
import urllib.request

from chroot_distro.arch import platform_from_arch
from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.helpers.docker.cache import (
    layer_cache_path,
    load_manifest_cache,
)
from chroot_distro.helpers.docker.media import (
    OCI_MANIFEST_MEDIA,
    canonical_json,
)
from chroot_distro.helpers.docker.refs import parse_image_ref
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_note,
    auth_opener,
    get_auth_token,
    opener,
    push_denied_msg,
)
from chroot_distro.helpers.download import (
    is_retryable_http_error,
    retry_http,
)
from chroot_distro.message import (
    C,
    is_quiet,
    log_info,
)
from chroot_distro.progress import (
    clear_bar,
    fmt_size,
)

# Default chunk size for chunked blob uploads (10 MiB). Overridable via
# CD_PUSH_CHUNK_SIZE (bytes). Layers at or above this size are uploaded in
# chunks; smaller blobs use the monolithic PUT path.
_DEFAULT_PUSH_CHUNK_SIZE = 10 * 1024 * 1024

# Connection/transport errors worth retrying.
def _push_chunk_size() -> int:
    raw = os.environ.get("CD_PUSH_CHUNK_SIZE", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return _DEFAULT_PUSH_CHUNK_SIZE


def _push_max_retries() -> int:
    from chroot_distro.constants import download_max_retries

    return download_max_retries()


def _is_retryable(exc: BaseException) -> bool:
    """Return True for transient registry or connection failures."""
    return is_retryable_http_error(exc)


def _with_retry(operation: typing.Callable[[], typing.Any], what: str) -> typing.Any:
    """Run *operation*, retrying transient failures."""
    return retry_http(operation, what=what, max_retries=_push_max_retries() + 1, retry_delay=5)


def _resolve_upload_url(base: str, location: str) -> str:
    """Resolve the Location header from POST /v2/<repo>/blobs/uploads/."""
    if not location:
        raise RuntimeError("Registry did not return an upload Location header.")
    if location.startswith(("http://", "https://")):
        return location
    if location.startswith("/"):
        return base + location
    return base.rstrip("/") + "/" + location


def _blob_exists(
    repo: str,
    digest: str,
    token: str,
    base: str,
    insecure: bool = False,
) -> bool:
    """Return True iff blob *digest* already exists on the registry."""
    url = f"{base}/v2/{repo}/blobs/{digest}"
    headers = {**_ua()}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _do() -> bool:
        req = urllib.request.Request(url, method="HEAD", headers=headers)
        try:
            op = auth_opener() if not insecure else opener(insecure)
            with op.open(req) as resp:
                return bool(200 <= resp.status < 300)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    return bool(_with_retry(_do, f"check {digest[:19]}"))


class _ProgressReader:
    """File wrapper that draws an upload progress bar as read() runs."""

    def __init__(self, fh: typing.BinaryIO, total: int, label: str):
        self._fh = fh
        self.total = total
        self.sent = 0
        self._label = label
        self._tty = sys.stderr.isatty() and not is_quiet()
        self._last_shown = 0

    def _maybe_draw(self, final: bool = False) -> None:
        if not self._tty:
            return
        if not final and self.sent - self._last_shown < 262144:
            return
        self._last_shown = self.sent
        pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"
        if self.total:
            pct = min(self.sent * 100 // self.total, 100)
            bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
            line = (
                f"\r{pfx}{self._label}: [{bar}] {pct:3d}%  "
                f"{fmt_size(self.sent)} / "
                f"{fmt_size(self.total)}\033[K{C['RST']}"
            )
        else:
            line = f"\r{pfx}{self._label}: {fmt_size(self.sent)} uploaded...\033[K{C['RST']}"
        sys.stderr.write(line)
        sys.stderr.flush()

    def read(self, size: int = -1) -> bytes:
        data = self._fh.read(size)
        self.sent += len(data)
        self._maybe_draw(final=(len(data) == 0))
        return data


def _upload_blob_bytes(
    repo: str,
    digest: str,
    data: bytes,
    token: str,
    base: str,
    insecure: bool = False,
) -> None:
    """Upload a small in-memory blob (POST + monolithic PUT, retry-wrapped)."""
    headers = _auth_headers(token)

    def _do() -> None:
        upload_url = _open_upload_session(base, repo, headers, insecure=insecure)
        full_put_url = _with_digest(upload_url, digest)
        put_req = urllib.request.Request(
            full_put_url,
            data=data,
            method="PUT",
            headers={
                **headers,
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(data)),
            },
        )
        op = auth_opener() if not insecure else opener(insecure)
        with op.open(put_req) as resp:
            if not 200 <= resp.status < 300:
                raise RuntimeError(f"Blob upload failed for {digest}: HTTP {resp.status}")

    _with_retry(_do, f"upload {digest[:19]}")


def _auth_headers(token: str) -> dict[str, str]:
    headers = {**_ua()}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _open_upload_session(base: str, repo: str, headers: dict[str, str], insecure: bool = False) -> str:
    """POST a new blob upload session and return the upload URL."""
    post_req = urllib.request.Request(
        f"{base}/v2/{repo}/blobs/uploads/",
        data=b"",
        method="POST",
        headers={**headers, "Content-Length": "0"},
    )
    op = auth_opener() if not insecure else opener(insecure)
    with op.open(post_req) as resp:
        location = resp.headers.get("Location", "")
    return _resolve_upload_url(base, location)


def _range_end(range_header: str) -> int | None:
    """Parse the end offset from a registry Range header like '0-1023'."""
    if not range_header or "-" not in range_header:
        return None
    try:
        return int(range_header.rsplit("-", 1)[1])
    except ValueError:
        return None


def _with_digest(url: str, digest: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}digest={urllib.parse.quote(digest, safe='')}"


def _upload_blob_monolithic(
    base: str,
    repo: str,
    digest: str,
    file_path: str,
    headers: dict[str, str],
    size: int,
    label: str,
    insecure: bool = False,
) -> None:
    """POST a session then send the whole blob in one PUT (retry-wrapped)."""

    def _do() -> None:
        upload_url = _open_upload_session(base, repo, headers, insecure=insecure)
        put_url = _with_digest(upload_url, digest)
        with open(file_path, "rb") as fh:
            reader = _ProgressReader(fh, size, label or digest[:19])
            put_req = urllib.request.Request(
                put_url,
                data=reader,
                method="PUT",
                headers={
                    **headers,
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                },
            )
            op = auth_opener() if not insecure else opener(insecure)
            with op.open(put_req) as resp:
                if not 200 <= resp.status < 300:
                    raise RuntimeError(f"Blob upload failed for {digest}: HTTP {resp.status}")

    _with_retry(_do, f"upload {label or digest[:19]}")


def _upload_blob_chunked(
    base: str,
    repo: str,
    digest: str,
    file_path: str,
    headers: dict[str, str],
    size: int,
    label: str,
    insecure: bool = False,
) -> None:
    """Upload a blob in PATCH chunks, resuming on transient failure.

    The registry acknowledges each PATCH with a new upload Location and a
    Range header giving the last byte stored. On a transient failure the
    session is reopened only if needed and the upload continues from the
    acknowledged offset, so a dropped connection does not restart the
    whole layer.
    """
    chunk_size = _push_chunk_size()
    max_retries = _push_max_retries()
    progress = _ProgressReader(typing.cast(typing.BinaryIO, None), size, label or digest[:19])

    upload_url = _with_retry(
        lambda: _open_upload_session(base, repo, headers, insecure=insecure), f"open upload {label}"
    )
    offset = 0
    attempt = 0

    with open(file_path, "rb") as fh:
        try:
            while offset < size:
                fh.seek(offset)
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                end = offset + len(chunk) - 1
                patch_req = urllib.request.Request(
                    upload_url,
                    data=chunk,
                    method="PATCH",
                    headers={
                        **headers,
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"{offset}-{end}",
                    },
                )
                try:
                    op = auth_opener() if not insecure else opener(insecure)
                    with op.open(patch_req) as resp:
                        if not 200 <= resp.status < 300:
                            raise RuntimeError(f"Chunk upload failed for {digest}: HTTP {resp.status}")
                        next_url = resp.headers.get("Location", "")
                        acked = _range_end(resp.headers.get("Range", ""))
                except BaseException as exc:
                    if not _is_retryable(exc) or attempt >= max_retries:
                        raise
                    attempt += 1
                    delay = min(2**attempt, 30)
                    log_info(
                        f"{label or digest[:19]}: chunk at {offset} failed ({exc}); "
                        f"retry {attempt}/{max_retries} in {delay}s..."
                    )
                    time.sleep(delay)
                    continue
                attempt = 0
                if next_url:
                    upload_url = _resolve_upload_url(base, next_url)
                # Advance by what the registry acknowledged when available,
                # else by the chunk we just sent.
                offset = (acked + 1) if acked is not None and acked >= offset else (end + 1)
                progress.sent = offset
                progress._maybe_draw(final=False)

            put_url = _with_digest(upload_url, digest)

            def _finalize() -> None:
                put_req = urllib.request.Request(
                    put_url,
                    data=b"",
                    method="PUT",
                    headers={**headers, "Content-Length": "0"},
                )
                op = auth_opener() if not insecure else opener(insecure)
                with op.open(put_req) as resp:
                    if not 200 <= resp.status < 300:
                        raise RuntimeError(f"Blob finalize failed for {digest}: HTTP {resp.status}")

            _with_retry(_finalize, f"finalize {label or digest[:19]}")
            progress.sent = size
            progress._maybe_draw(final=True)
        finally:
            clear_bar()


def _upload_blob_file(
    repo: str,
    digest: str,
    file_path: str,
    token: str,
    base: str,
    insecure: bool = False,
    label: str = "",
) -> None:
    """Upload a blob from *file_path*.

    Blobs at or above the configured chunk size are uploaded in chunks
    (resumable); smaller blobs use a single retry-wrapped PUT.
    """
    headers = _auth_headers(token)
    size = os.path.getsize(file_path)

    if size >= _push_chunk_size():
        _upload_blob_chunked(base, repo, digest, file_path, headers, size, label, insecure=insecure)
    else:
        try:
            _upload_blob_monolithic(base, repo, digest, file_path, headers, size, label, insecure=insecure)
        finally:
            clear_bar()


def _put_manifest(
    repo: str,
    reference: str,
    body: bytes,
    media_type: str,
    token: str,
    base: str,
    insecure: bool = False,
) -> str:
    """PUT a manifest at <reference> (tag or digest). Returns the registry
    digest from the Docker-Content-Digest header, if provided."""
    url = f"{base}/v2/{repo}/manifests/{reference}"
    headers = {
        **_ua(),
        "Content-Type": media_type,
        "Content-Length": str(len(body)),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _do() -> str:
        req = urllib.request.Request(url, data=body, method="PUT", headers=headers)
        op = auth_opener() if not insecure else opener(insecure)
        with op.open(req) as resp:
            if not 200 <= resp.status < 300:
                raise RuntimeError(f"Manifest upload failed: HTTP {resp.status}")
            return str(resp.headers.get("Docker-Content-Digest", ""))

    return str(_with_retry(_do, "upload manifest"))


def _strip_private_keys(d: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Return a shallow copy of *d* without keys starting with '_'.

    `_get_manifest` stuffs the response Content-Type into `_ct` for
    internal use; that key must not be serialised back to the registry.
    """
    return {k: v for k, v in d.items() if not k.startswith("_")}


def push_image(image_ref: str, arch: str, insecure: bool = False) -> dict[str, typing.Any]:
    """Push a built image (resolved from the manifest cache) to its registry.

    The image must have been produced by `chroot-distro build` under
    exactly this *image_ref* and *arch*; `build` stores the manifest
    in MANIFEST_CACHE_DIR and the layer + config blobs in
    LAYER_CACHE_DIR using the same digests we transmit here.
    """
    manifest, repo, image_config = load_manifest_cache(image_ref, platform_from_arch(arch))
    if manifest is None:
        raise RuntimeError(
            f"No cached manifest for '{image_ref}' ({arch}). Build image "
            f"first with: {PROGRAM_NAME} build -t {image_ref}"
        )
    assert repo is not None

    layers = manifest.get("layers", [])
    if not layers:
        raise RuntimeError(f"Cached manifest for '{image_ref}' has no filesystem layers.")

    missing = [layer["digest"] for layer in layers if not os.path.isfile(layer_cache_path(layer["digest"]))]
    if missing:
        raise RuntimeError(
            f"Cannot push '{image_ref}': {len(missing)} layer blob(s) are "
            f"missing from the local cache (first missing: {missing[0]}). "
            f"Rebuild the image to repopulate the cache."
        )

    registry, _, tag = parse_image_ref(image_ref)

    # Re-canonicalize the image config and verify the digest. The manifest
    # carries config.digest, which the registry verifies against the bytes
    # we PUT. Round-tripping the dict through json.dump+json.load preserves
    # all keys, so the canonical form is reproducible here.
    config_bytes = canonical_json(image_config)
    expected_cfg_digest = manifest.get("config", {}).get("digest", "")
    actual_cfg_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    if expected_cfg_digest != actual_cfg_digest:
        raise RuntimeError(
            f"Image config digest mismatch (cached manifest expects "
            f"{expected_cfg_digest}, regenerated bytes hash to "
            f"{actual_cfg_digest}). The local cache appears corrupted; "
            f"rebuild the image."
        )

    log_info(f"Authenticating with registry{auth_note()}...")
    try:
        token, base = get_auth_token(repo, registry, actions="pull,push", insecure=insecure)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(push_denied_msg(image_ref, exc.code)) from exc
        raise

    n_layers = len(layers)
    bytes_uploaded = 0

    for i, layer in enumerate(layers):
        digest = layer["digest"]
        short_id = digest.split(":")[-1][:12]
        path = layer_cache_path(digest)
        size = os.path.getsize(path)

        try:
            if _blob_exists(repo, digest, token, base, insecure=insecure):
                log_info(f"{short_id}: Layer {i + 1}/{n_layers} already exists on registry, skipping upload.")
                continue

            log_info(f"{short_id}: Uploading layer {i + 1}/{n_layers} ({fmt_size(size)})...")
            _upload_blob_file(
                repo,
                digest,
                path,
                token,
                base,
                insecure=insecure,
                label=short_id,
            )
            bytes_uploaded += size
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RuntimeError(push_denied_msg(image_ref, exc.code)) from exc
            raise

    cfg_short = expected_cfg_digest.split(":")[-1][:12]
    try:
        if _blob_exists(repo, expected_cfg_digest, token, base, insecure=insecure):
            log_info(f"{cfg_short}: Image config already exists on registry, skipping upload.")
        else:
            log_info(f"{cfg_short}: Uploading image config ({fmt_size(len(config_bytes))})...")
            _upload_blob_bytes(
                repo,
                expected_cfg_digest,
                config_bytes,
                token,
                base,
                insecure=insecure,
            )
            bytes_uploaded += len(config_bytes)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(push_denied_msg(image_ref, exc.code)) from exc
        raise

    manifest_media = manifest.get("mediaType") or OCI_MANIFEST_MEDIA
    manifest_bytes = canonical_json(_strip_private_keys(manifest))
    log_info(f"Uploading manifest for tag '{tag}' ({fmt_size(len(manifest_bytes))})...")
    try:
        registry_digest = _put_manifest(
            repo,
            tag,
            manifest_bytes,
            manifest_media,
            token,
            base,
            insecure=insecure,
        )
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(push_denied_msg(image_ref, exc.code)) from exc
        raise
    bytes_uploaded += len(manifest_bytes)

    return {
        "manifest_digest": registry_digest,
        "bytes_uploaded": bytes_uploaded,
        "registry": registry or "docker.io",
        "repo": repo,
        "tag": tag,
    }
