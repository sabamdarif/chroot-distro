import contextlib
import functools
import hashlib
import json
import logging
import os
import shutil
import signal
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from chroot_distro.atomic import atomic_replace
from chroot_distro.helpers.docker.cache import layer_cache_path
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_opener,
    opener,
    registry_base_url,
)
from chroot_distro.helpers.download import (
    _SOCKET_TIMEOUT,
    _compute_segments,
    _download_segment,
    _FallbackToSingleError,
    _LiveResponses,
    _probe_url,
    _ProbeResult,
    _Segment,
    is_retryable_http_error,
    retry_http,
)
from chroot_distro.helpers.tar_extract import extract_tar_to_rootfs
from chroot_distro.message import log_info
from chroot_distro.progress import REDRAW_THRESHOLD_BYTES, AggregateByteProgress, clear_bar, draw_bytes_bar

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_BACKOFF = (2, 5, 10)  # seconds to wait between retries

# Read buffer size per I/O call — 256 KiB balances syscall overhead
# against memory use and gives threads more time between lock
# acquisitions on the shared progress counter.
_READ_CHUNK = 262144

# Errors worth retrying — transient network / SSL issues.
_RETRYABLE = (
    ssl.SSLError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    TimeoutError,
    OSError,
)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* looks like a transient network failure."""
    return is_retryable_http_error(exc)


def _probe_blob(url: str, headers: dict[str, str], insecure: bool = False) -> _ProbeResult | None:
    """Send HEAD (or fallback GET Range:0-0) to discover size + Range support.

    Uses ``auth_opener()`` (or ``opener(insecure)``) so that registry auth tokens
    and cross-host redirect stripping are handled correctly.

    Returns *None* on any network error so the caller can fall back silently.
    """
    op = auth_opener() if not insecure else opener(insecure)
    open_fn = functools.partial(op.open, timeout=_SOCKET_TIMEOUT)
    return _probe_url(url, headers, open_fn=open_fn)


def download_blob(
    repo: str,
    digest: str,
    token: str,
    base: str = "",
    *,
    byte_progress: AggregateByteProgress | None = None,
    abort_event: threading.Event | None = None,
    live_responses: "_LiveResponses | None" = None,
    connections: int = 1,
    insecure: bool = False,
) -> str:
    """Download a blob to the layer cache; return the local file path.

    Streams the bytes through sha256 and verifies the result against the
    expected *digest* before promoting the .tmp file.

    Retries up to the configured retry limit times on transient network / SSL
    failures with exponential backoff.
    """
    from chroot_distro.constants import download_max_retries, download_rate_limit
    from chroot_distro.rate_limit import TokenBucket

    max_retries = download_max_retries()
    rate = download_rate_limit()
    bucket = TokenBucket(rate) if rate > 0 else None

    dest = layer_cache_path(digest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.isfile(dest):
        return dest

    if ":" not in digest:
        raise RuntimeError(f"Malformed layer digest '{digest}'.")
    algo, expected_hex = digest.split(":", 1)
    if algo.lower() != "sha256":
        raise RuntimeError(f"Unsupported layer digest algorithm '{algo}' (only sha256 is supported).")

    if base and base.startswith(("http://", "https://")):
        url_base = base
    else:
        url_base = registry_base_url(base or "", insecure=insecure)
    url = f"{url_base}/v2/{repo}/blobs/{digest}"

    if connections > 1:
        chunks_meta_path = f"{dest}.chunks.json"
        segments = None
        try:
            probe_headers = {**_ua()}
            if token:
                probe_headers["Authorization"] = f"Bearer {token}"
            probe = _probe_blob(url, probe_headers, insecure=insecure)

            if probe is not None and probe.range_ok and probe.content_length > 0:
                if os.path.isfile(chunks_meta_path):
                    try:
                        with open(chunks_meta_path, encoding="utf-8") as f:
                            meta = json.load(f)
                        if meta.get("total") == probe.content_length:
                            segments = [
                                _Segment(
                                    index=s["index"],
                                    start=s["start"],
                                    end=s["end"],
                                    tmp_path=s["tmp_path"],
                                )
                                for s in meta.get("segments", [])
                            ]
                    except Exception as exc:
                        log.debug("Failed to load docker layer download metadata: %s", exc)

                if not segments:
                    for i in range(connections + 5):
                        with contextlib.suppress(OSError):
                            os.remove(f"{dest}.chunk{i}.tmp")
                    with contextlib.suppress(OSError):
                        os.remove(chunks_meta_path)

                    segments = _compute_segments(probe.content_length, connections, dest)
                    if len(segments) == 1:
                        raise _FallbackToSingleError

                    try:
                        meta = {
                            "total": probe.content_length,
                            "segments": [
                                {
                                    "index": s.index,
                                    "start": s.start,
                                    "end": s.end,
                                    "tmp_path": s.tmp_path,
                                }
                                for s in segments
                            ],
                        }
                        with open(chunks_meta_path, "w", encoding="utf-8") as f:
                            json.dump(meta, f)
                    except Exception as exc:
                        log.warning("Failed to save docker layer download metadata: %s", exc)

                if len(segments) == 1:
                    raise _FallbackToSingleError

                progress = byte_progress or AggregateByteProgress(probe.content_length, label=expected_hex[:12])
                prev_sigint = signal.getsignal(signal.SIGINT)
                try:
                    # Pre-fill byte progress with already downloaded bytes
                    already_downloaded = 0
                    for seg in segments:
                        if os.path.isfile(seg.tmp_path):
                            already_downloaded += os.path.getsize(seg.tmp_path)
                    if already_downloaded:
                        progress.add(already_downloaded)

                    original_parsed = urllib.parse.urlparse(url)
                    final_parsed = urllib.parse.urlparse(probe.final_url)
                    seg_headers = {**_ua()}
                    if token and original_parsed.netloc == final_parsed.netloc:
                        seg_headers["Authorization"] = f"Bearer {token}"

                    local_abort = abort_event or threading.Event()
                    live = live_responses or _LiveResponses(lock=threading.Lock(), responses=set())

                    def _on_sigint(_signum, _frame):
                        local_abort.set()
                        live.close_all()
                        raise KeyboardInterrupt

                    with contextlib.suppress(ValueError):
                        signal.signal(signal.SIGINT, _on_sigint)
                    pool = ThreadPoolExecutor(max_workers=len(segments))
                    try:
                        futures = {
                            pool.submit(
                                _download_segment,
                                seg,
                                probe.final_url,
                                seg_headers,
                                progress,
                                local_abort,
                                bucket,
                                live,
                                insecure=insecure,
                            ): seg
                            for seg in segments
                        }
                        for future in as_completed(futures):
                            future.result()
                    except KeyboardInterrupt:
                        local_abort.set()
                        live.close_all()
                        pool.shutdown(wait=False, cancel_futures=True)
                        raise
                    except Exception as exc:
                        local_abort.set()
                        live.close_all()
                        pool.shutdown(wait=False, cancel_futures=True)
                        raise _FallbackToSingleError from exc
                    else:
                        pool.shutdown(wait=True)

                    success = False
                    try:
                        with atomic_replace(dest) as tmp:
                            with open(tmp, "wb") as out:
                                for seg in sorted(segments, key=lambda s: s.index):
                                    with open(seg.tmp_path, "rb") as inp:
                                        shutil.copyfileobj(inp, out, length=1 << 20)
                                out.flush()
                                os.fsync(out.fileno())

                            # Verify the temp file BEFORE replacing dest
                            hasher = hashlib.sha256()
                            with open(tmp, "rb") as fh_verify:
                                for chunk in iter(lambda: fh_verify.read(262144), b""):
                                    hasher.update(chunk)
                            actual_hex = hasher.hexdigest()
                            if actual_hex != expected_hex.lower():
                                raise RuntimeError(
                                    f"Layer integrity check failed for digest '{digest}': "
                                    f"expected {expected_hex}, got {actual_hex}."
                                )
                        success = True
                        return dest
                    finally:
                        if success:
                            for seg in segments:
                                with contextlib.suppress(OSError):
                                    os.remove(seg.tmp_path)
                            with contextlib.suppress(OSError):
                                os.remove(chunks_meta_path)
                finally:
                    with contextlib.suppress(NameError, ValueError):
                        signal.signal(signal.SIGINT, prev_sigint)
                    if byte_progress is None:
                        progress.clear()
        except _FallbackToSingleError as exc:
            log.debug("Multi-connection download not supported or failed, falling back to single connection: %s", exc)
            if connections > 1:
                log_info(
                    f"{expected_hex[:12]}: registry does not support ranged requests; "
                    f"downloading this layer over a single connection."
                )
        except Exception:
            raise

    headers = {**_ua()}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)

    def _attempt():
        if abort_event is not None and abort_event.is_set():
            raise KeyboardInterrupt
        hasher = hashlib.sha256()
        with atomic_replace(dest) as tmp:
            op = auth_opener() if not insecure else opener(insecure)
            with op.open(req, timeout=_SOCKET_TIMEOUT) as resp, open(tmp, "wb") as fh:
                if live_responses is not None:
                    live_responses.add(resp)
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                unsent = 0  # bytes not yet reported to aggregate
                if byte_progress is None:
                    draw_bytes_bar(0, total, noun="downloaded")
                try:
                    while True:
                        if abort_event is not None and abort_event.is_set():
                            raise KeyboardInterrupt
                        chunk = resp.read(_READ_CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
                        hasher.update(chunk)
                        chunk_len = len(chunk)
                        downloaded += chunk_len
                        if bucket:
                            bucket.consume(chunk_len)
                        if byte_progress is not None:
                            unsent += chunk_len
                            if unsent >= REDRAW_THRESHOLD_BYTES:
                                byte_progress.add(unsent)
                                unsent = 0
                        else:
                            draw_bytes_bar(downloaded, total, noun="downloaded")
                    # flush remaining unsent bytes
                    if byte_progress is not None and unsent:
                        byte_progress.add(unsent)
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    if live_responses is not None:
                        live_responses.discard(resp)
                    if byte_progress is None:
                        clear_bar()
            actual_hex = hasher.hexdigest()
            if actual_hex != expected_hex.lower():
                raise RuntimeError(
                    f"Layer integrity check failed for digest '{digest}': expected {expected_hex}, got {actual_hex}."
                )

    retry_http(
        _attempt,
        what=f"Downloading layer {expected_hex[:12]}",
        max_retries=max_retries,
        retry_delay=5,
        abort_event=abort_event,
    )
    return dest


def apply_layer(layer_path: str, rootfs_dir: str) -> None:
    """Apply one OCI/Docker layer (gzipped tar) onto rootfs_dir."""
    extract_tar_to_rootfs(layer_path, rootfs_dir, handle_whiteouts=True)
