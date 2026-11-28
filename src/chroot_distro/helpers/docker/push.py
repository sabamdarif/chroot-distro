# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Upload a built image to a registry: blobs first, manifest last.

`push_image` pushes what `build` already produced. The manifest cache is the source of
truth for the selected tag and architecture. A missing layer is refused with a
rebuild hint.

Ordering is the registry's rule, not a preference: a manifest naming a blob the registry
does not hold is rejected, so every layer and the config go up first and the manifest
last. Each blob is HEAD-checked first, which is how a re-push of a shared base costs
nothing.

The image config is re-serialised with `canonical_json` and checked against the
cached descriptor. Each missing remote layer is copied from a pinned cache entry
to a temporary file and verified there before its bytes go to the registry.

Small blobs use one PUT. Larger blobs are sent in PATCH chunks. After a failed
PATCH, a status GET supplies the confirmed offset and the next upload URL.
A digest-addressed HEAD checks whether a final PUT with a lost reply committed.

Only transient failures retry. A 401 or 403 anywhere becomes `push_denied_msg`, which
names whether credentials were supplied, since "denied" means different things with and
without them.
"""

import hashlib
import http.client
import os
import re
import stat
import sys
import tempfile
import typing
import urllib.error
import urllib.parse
import urllib.request
from contextlib import ExitStack

from chroot_distro import dirfd
from chroot_distro.arch import platform_from_arch
from chroot_distro.constants import BASE_CACHE_DIR, IS_TERMUX, LAYER_CACHE_DIR, PROGRAM_NAME, RUNTIME_DIR
from chroot_distro.helpers.docker.cache import (
    layer_cache_path,
    load_manifest_cache,
)
from chroot_distro.helpers.docker.media import (
    DOCKER_MANIFEST_MEDIA,
    OCI_MANIFEST_MEDIA,
    canonical_json,
    manifest_layers,
    read_descriptor,
)
from chroot_distro.helpers.docker.refs import parse_tag_reference
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_note,
    auth_opener,
    get_auth_token,
    insecure_for,
    opener,
    push_denied_msg,
    rate_limited_msg,
    registry_request,
    resolve_registry_url,
    same_auth_origin,
)
from chroot_distro.helpers.download import (
    NETWORK_ERRORS,
    NETWORK_TIMEOUT,
    is_retryable_http_error,
    retry_after,
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

# HTTP success range for a pushed object, and the auth-denied codes that
# become `push_denied_msg` whether or not credentials were supplied.
_OK_RANGE = range(200, 300)
_DENIED_CODES = (401, 403)

# Redraw the upload bar at most every 256 KiB moved.
_PROGRESS_THROTTLE_BYTES = 262144


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


def _resolve_upload_url(base: str, source: str, location: str, *, insecure: bool) -> str:
    """Resolve an upload Location relative to the response that supplied it."""
    if not location:
        raise RuntimeError("Registry did not return an upload Location header.")
    target = resolve_registry_url(source, location, insecure=insecure)
    return resolve_registry_url(base, target, insecure=insecure, absolute=True)


def _headers_for(headers: dict[str, str], base: str, url: str) -> dict[str, str]:
    """*headers* for a request to *url*: the token only on the registry.

    The credential was issued for the registry at *base*, and the upload
    Location is a header the registry's answer named, so an
    absolute one can point anywhere. The request itself still goes (a
    registry may hand out a pre-signed upload URL on a store of its own),
    it simply goes without the credential.
    """
    if same_auth_origin(base, url):
        return headers
    return {k: v for k, v in headers.items() if k != "Authorization"}


def _blob_exists(
    repo: str,
    digest: str,
    auth: str,
    base: str,
    insecure: bool = False,
) -> bool:
    """Return True iff blob *digest* already exists on the registry."""
    url = f"{base}/v2/{repo}/blobs/{digest}"
    headers = {**_ua()}
    if auth:
        headers["Authorization"] = auth

    def _do() -> bool:
        req = registry_request(url, method="HEAD", headers=headers)
        try:
            op = auth_opener() if not insecure else opener(insecure)
            with op.open(req) as resp:
                return bool(resp.status == 200)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                exc.close()
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
        if not final and self.sent - self._last_shown < _PROGRESS_THROTTLE_BYTES:
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
    auth: str,
    base: str,
    insecure: bool = False,
) -> None:
    """Upload a small in-memory blob (POST + monolithic PUT, retry-wrapped)."""
    headers = _auth_headers(auth)

    def _do() -> None:
        upload_url = _open_upload_session(base, repo, headers, insecure=insecure)
        full_put_url = _with_digest(upload_url, digest)
        put_req = registry_request(
            full_put_url,
            data=data,
            method="PUT",
            headers={
                **_headers_for(headers, base, full_put_url),
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(data)),
            },
        )
        op = auth_opener() if not insecure else opener(insecure)
        with op.open(put_req) as resp:
            if resp.status not in _OK_RANGE:
                raise RuntimeError(f"Blob upload failed for {digest}: HTTP {resp.status}")

    _with_retry(_do, f"upload {digest[:19]}")


def _auth_headers(auth: str) -> dict[str, str]:
    headers = {**_ua()}
    if auth:
        headers["Authorization"] = auth
    return headers


def _open_upload_session(base: str, repo: str, headers: dict[str, str], insecure: bool = False) -> str:
    """POST a new blob upload session and return the upload URL."""
    post_req = registry_request(
        f"{base}/v2/{repo}/blobs/uploads/",
        data=b"",
        method="POST",
        headers={**headers, "Content-Length": "0"},
    )
    op = auth_opener() if not insecure else opener(insecure)
    with op.open(post_req) as resp:
        if resp.status != 202:
            raise RuntimeError(f"Opening a blob upload failed: HTTP {resp.status}")
        location = resp.headers.get("Location", "")
        return _resolve_upload_url(base, resp.geturl(), location, insecure=insecure)


def _range_end(range_header: str) -> int | None:
    """Parse the end offset from a registry Range header like '0-1023'."""
    match = re.fullmatch(r"(?:bytes=)?0-([0-9]{1,19})", range_header.strip())
    return int(match[1]) if match else None


def _with_digest(url: str, digest: str) -> str:
    path, _, query = url.partition("?")
    prefix = f"{query}&" if query else ""
    return f"{path}?{prefix}digest={urllib.parse.quote(digest, safe='')}"


def _upload_blob_monolithic(
    base: str,
    repo: str,
    digest: str,
    fh: typing.BinaryIO,
    headers: dict[str, str],
    size: int,
    label: str,
    insecure: bool = False,
) -> None:
    """POST a session then send the whole blob in one PUT (retry-wrapped)."""
    # A registry may re-hash or copy the blob before answering the PUT, which
    # grows with its size, so the commit gets a longer wait than the rest.
    timeout = max(NETWORK_TIMEOUT, size / (1024 * 1024))

    def _do() -> None:
        upload_url = _open_upload_session(base, repo, headers, insecure=insecure)
        put_url = _with_digest(upload_url, digest)
        fh.seek(0)
        reader = _ProgressReader(fh, size, label or digest[:19])
        put_req = registry_request(
            put_url,
            data=reader,
            method="PUT",
            headers={
                **_headers_for(headers, base, put_url),
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
        )
        op = auth_opener() if not insecure else opener(insecure)
        with op.open(put_req, timeout=timeout) as resp:
            if resp.status not in _OK_RANGE:
                raise RuntimeError(f"Blob upload failed for {digest}: HTTP {resp.status}")

    _with_retry(_do, f"upload {label or digest[:19]}")


def _upload_blob_chunked(
    base: str,
    repo: str,
    digest: str,
    fh: typing.BinaryIO,
    headers: dict[str, str],
    size: int,
    label: str,
    insecure: bool = False,
) -> None:
    """Send the blob in PATCH chunks and recover from an uncertain reply."""
    chunk_size = _push_chunk_size()
    progress = _ProgressReader(typing.cast(typing.BinaryIO, None), size, label or digest[:19])
    op = auth_opener() if not insecure else opener(insecure)
    auth = headers.get("Authorization", "")

    def _open() -> str:
        return _open_upload_session(base, repo, headers, insecure=insecure)

    def _status(url: str) -> tuple[str, int]:
        req = registry_request(url, method="GET", headers=_headers_for(headers, base, url))
        with op.open(req) as resp:
            if resp.status != 204:
                raise RuntimeError(f"Registry upload status failed: HTTP {resp.status}")
            acked = _range_end(resp.headers.get("Range", ""))
            if acked is None:
                raise RuntimeError("Registry upload status has an invalid Range header.")
            location = _resolve_upload_url(base, resp.geturl(), resp.headers.get("Location", ""), insecure=insecure)
            return location, acked

    upload_url = _with_retry(_open, f"open upload {label}")
    offset = 0

    def _send_chunk(start: int, chunk: bytes) -> int:
        end = start + len(chunk) - 1
        recovering = False

        def _attempt() -> int:
            nonlocal upload_url, recovering
            if recovering:
                upload_url, acked = _status(upload_url)
                if not start <= acked + 1 <= end + 1:
                    raise RuntimeError("Registry upload status is outside the attempted byte range.")
                # Distribution reports 0-0 for both an empty session and one byte.
                if start == acked == 0:
                    upload_url = _open()
                elif acked + 1 > start:
                    return acked + 1
            try:
                patch_req = registry_request(
                    upload_url,
                    data=chunk,
                    method="PATCH",
                    headers={
                        **_headers_for(headers, base, upload_url),
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"{start}-{end}",
                    },
                )
                with op.open(patch_req) as resp:
                    if resp.status != 202:
                        raise RuntimeError(f"Chunk upload failed for {digest}: HTTP {resp.status}")
                    if _range_end(resp.headers.get("Range", "")) != end:
                        raise RuntimeError("Registry did not acknowledge the full upload chunk.")
                    next_url = resp.headers.get("Location", "")
                    if next_url:
                        upload_url = _resolve_upload_url(base, resp.geturl(), next_url, insecure=insecure)
            except NETWORK_ERRORS as exc:
                recovering = True
                if isinstance(exc, urllib.error.HTTPError) and exc.code == 416:
                    exc.close()
                    raise http.client.HTTPException("Registry requested upload status after HTTP 416.") from None
                raise
            return end + 1

        return int(_with_retry(_attempt, f"upload {label or digest[:19]} at byte {start}"))

    try:
        while offset < size:
            fh.seek(offset)
            chunk = fh.read(min(chunk_size, size - offset))
            if not chunk:
                raise RuntimeError(f"Layer ended before {size} bytes: {digest}")
            offset = _send_chunk(offset, chunk)
            progress.sent = offset
            progress._maybe_draw(final=False)

        put_url = _with_digest(upload_url, digest)
        commit_timeout = max(NETWORK_TIMEOUT, size / (1024 * 1024))
        uncertain = False

        def _finalize() -> None:
            nonlocal uncertain
            if uncertain and _blob_exists(repo, digest, auth, base, insecure=insecure):
                return
            try:
                put_req = registry_request(
                    put_url,
                    data=b"",
                    method="PUT",
                    headers={**_headers_for(headers, base, put_url), "Content-Length": "0"},
                )
                with op.open(put_req, timeout=commit_timeout) as resp:
                    if resp.status != 201:
                        raise RuntimeError(f"Blob finalize failed for {digest}: HTTP {resp.status}")
            except NETWORK_ERRORS as exc:
                uncertain = uncertain or _is_retryable(exc)
                raise

        try:
            _with_retry(_finalize, f"finalize {label or digest[:19]}")
        except NETWORK_ERRORS as exc:
            if (
                not uncertain
                or (retry_after(exc) or 0) > 0
                or (isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403, 429))
                or not _blob_exists(repo, digest, auth, base, insecure=insecure)
            ):
                raise
        progress.sent = size
        progress._maybe_draw(final=True)
    finally:
        clear_bar()


def _upload_blob_file(
    repo: str,
    digest: str,
    source: typing.BinaryIO,
    size: int,
    auth: str,
    base: str,
    insecure: bool = False,
    label: str = "",
) -> None:
    """Upload a blob from a verified stream.

    Blobs at or above the configured chunk size are uploaded in chunks
    (resumable); smaller blobs use a single retry-wrapped PUT.
    """
    headers = _auth_headers(auth)
    if size >= _push_chunk_size():
        _upload_blob_chunked(base, repo, digest, source, headers, size, label, insecure=insecure)
    else:
        try:
            _upload_blob_monolithic(base, repo, digest, source, headers, size, label, insecure=insecure)
        finally:
            clear_bar()


def _put_manifest(
    repo: str,
    reference: str,
    body: bytes,
    media_type: str,
    auth: str,
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
    if auth:
        headers["Authorization"] = auth

    def _do() -> str:
        req = registry_request(url, data=body, method="PUT", headers=headers)
        op = auth_opener() if not insecure else opener(insecure)
        with op.open(req) as resp:
            if resp.status not in _OK_RANGE:
                raise RuntimeError(f"Manifest upload failed: HTTP {resp.status}")
            return str(resp.headers.get("Docker-Content-Digest", ""))

    return str(_with_retry(_do, "upload manifest"))


def _refusal_msg(image_ref: str, ref: tuple[str, str, str], exc: urllib.error.HTTPError) -> str:
    """The message for a registry refusing the push with *exc*, or ''.

    401/403 is the registry refusing this account and 429 its rate limit;
    both become a RuntimeError carrying this message. Any other HTTP error
    is not a refusal this can explain, and propagates as itself for the
    command to report as a network error.
    """
    if exc.code in _DENIED_CODES:
        return push_denied_msg(image_ref, exc.code)
    if exc.code == 429:
        return rate_limited_msg(image_ref, ref, exc, action="push")
    return ""


def _strip_private_keys(d: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Return a shallow copy of *d* without keys starting with '_'.

    `_get_manifest` stuffs the response Content-Type into `_ct` for
    internal use; that key must not be serialised back to the registry.
    """
    return {k: v for k, v in d.items() if not k.startswith("_")}


def _check_layer_files(cache_fd: int, sizes: dict[str, int | None]) -> None:
    for digest, size in sizes.items():
        name = os.path.basename(layer_cache_path(digest))
        try:
            st = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise RuntimeError(f"Layer blob {digest} is missing from the local cache. Rebuild the image.") from None
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"Layer blob {digest} is not a regular cache file. Rebuild the image.")
        if st.st_size != size:
            raise RuntimeError(f"Cached layer size mismatch for {digest}. Rebuild the image.")


def _snapshot_layer(cache_fd: int, digest: str, size: int, snapshot: typing.BinaryIO) -> None:
    name = os.path.basename(layer_cache_path(digest))
    fd, _ = dirfd.open_regular_at(cache_fd, name, os.O_RDONLY)
    hasher = hashlib.sha256()
    copied = 0
    with os.fdopen(fd, "rb") as source:
        while chunk := source.read(min(1 << 18, size - copied + 1)):
            copied += len(chunk)
            if copied > size:
                break
            hasher.update(chunk)
            snapshot.write(chunk)
    if copied != size:
        raise RuntimeError(f"Cached layer size mismatch for {digest}. Rebuild the image.")
    if "sha256:" + hasher.hexdigest() != digest:
        raise RuntimeError(f"Cached layer digest mismatch for {digest}. Rebuild the image.")
    snapshot.seek(0)


def push_image(image_ref: str, arch: str, insecure: bool = False) -> dict[str, typing.Any]:
    """Push a built image (resolved from the manifest cache) to its registry.

    The image must have been produced by `chroot-distro build` under
    exactly this *image_ref* and *arch*; `build` stores the manifest
    in MANIFEST_CACHE_DIR and the layer + config blobs in
    LAYER_CACHE_DIR using the same digests we transmit here.
    """
    # The grammar first, as pull_image does, and a digest is no name to push
    # under. The repository comes from the reference and not from the cache
    # entry's `repo`: the entry is a file a guest can write on Termux, and the
    # repository is where the upload, the push-scoped token and the tag all go.
    parsed_ref = parse_tag_reference(image_ref)
    registry, repo, tag = parsed_ref.registry, parsed_ref.repo, parsed_ref.tag

    manifest, _cached_repo, image_config = load_manifest_cache(image_ref, platform_from_arch(arch))
    if manifest is None:
        raise RuntimeError(
            f"No cached manifest for '{image_ref}' ({arch}). Build image "
            f"first with: {PROGRAM_NAME} build -t {image_ref}"
        )

    _, sizes = manifest_layers(manifest)
    manifest_media = manifest.get("mediaType", OCI_MANIFEST_MEDIA)
    if manifest_media not in (OCI_MANIFEST_MEDIA, DOCKER_MANIFEST_MEDIA) or manifest.get("artifactType"):
        raise RuntimeError("Push requires a cached single-platform image manifest.")

    # Docker Hub is verified HTTPS whatever --allow-insecure says; every
    # upload helper below gets this answer.
    insecure = insecure_for(registry, insecure)

    # Re-canonicalize the image config and verify the digest. The manifest
    # carries config.digest, which the registry verifies against the bytes
    # we PUT. Round-tripping the dict through json.dump+json.load preserves
    # all keys, so the canonical form is reproducible here.
    config_bytes = canonical_json(image_config)
    expected_cfg_digest, expected_cfg_size = read_descriptor(manifest.get("config"), "Image config")
    actual_cfg_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    if expected_cfg_digest != actual_cfg_digest:
        raise RuntimeError(
            f"Image config digest mismatch (cached manifest expects "
            f"{expected_cfg_digest}, regenerated bytes hash to "
            f"{actual_cfg_digest}). The local cache appears corrupted; "
            f"rebuild the image."
        )
    if expected_cfg_size != len(config_bytes):
        raise RuntimeError("Cached image config size mismatch. Rebuild the image.")

    bytes_uploaded = 0
    with ExitStack() as stack:
        cache_fd = None
        if sizes:
            cache_root = RUNTIME_DIR if IS_TERMUX else BASE_CACHE_DIR
            parts = os.path.relpath(LAYER_CACHE_DIR, cache_root).split(os.sep)
            cache_fd = dirfd.opendir_under(cache_root, parts)
            if cache_fd is None:
                raise RuntimeError("Layer cache directory is unavailable. Rebuild the image.")
            stack.callback(os.close, cache_fd)
            _check_layer_files(cache_fd, sizes)
        log_info(f"Authenticating with registry{auth_note()}...")
        try:
            auth, base = get_auth_token(repo, registry, actions="pull,push", insecure=insecure)
            for i, (digest, size) in enumerate(sizes.items(), start=1):
                assert cache_fd is not None
                assert size is not None
                short_id = digest.split(":")[-1][:12]
                label = f"{short_id}: Layer {i}/{len(sizes)}"
                if _blob_exists(repo, digest, auth, base, insecure=insecure):
                    log_info(f"{label} already exists on registry, skipping upload.")
                    continue
                with tempfile.TemporaryFile() as snapshot:
                    _snapshot_layer(cache_fd, digest, size, snapshot)
                    log_info(f"{label}: Uploading ({fmt_size(size)})...")
                    _upload_blob_file(repo, digest, snapshot, size, auth, base, insecure=insecure, label=short_id)
                bytes_uploaded += size

            cfg_short = expected_cfg_digest.split(":")[-1][:12]
            if _blob_exists(repo, expected_cfg_digest, auth, base, insecure=insecure):
                log_info(f"{cfg_short}: Image config already exists on registry, skipping upload.")
            else:
                log_info(f"{cfg_short}: Uploading image config ({fmt_size(len(config_bytes))})...")
                _upload_blob_bytes(repo, expected_cfg_digest, config_bytes, auth, base, insecure=insecure)
                bytes_uploaded += len(config_bytes)

            manifest_bytes = canonical_json(_strip_private_keys(manifest))
            log_info(f"Uploading manifest for tag '{tag}' ({fmt_size(len(manifest_bytes))})...")
            registry_digest = _put_manifest(
                repo,
                tag,
                manifest_bytes,
                manifest_media,
                auth,
                base,
                insecure=insecure,
            )
        except urllib.error.HTTPError as exc:
            refusal = _refusal_msg(image_ref, (registry, repo, tag), exc)
            if refusal:
                raise RuntimeError(refusal) from exc
            raise
        bytes_uploaded += len(manifest_bytes)

    return {
        "manifest_digest": registry_digest,
        "bytes_uploaded": bytes_uploaded,
        "registry": registry or "docker.io",
        "repo": repo,
        "tag": tag,
    }
