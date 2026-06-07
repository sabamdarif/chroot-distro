import contextlib
import functools
import hashlib
import json
import os
import shutil
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from chroot_distro.atomic import atomic_replace
from chroot_distro.helpers.docker.cache import layer_cache_path
from chroot_distro.helpers.docker.transport import (
    _ua,
    auth_opener,
    registry_base_url,
)
from chroot_distro.helpers.download import (
    _SOCKET_TIMEOUT,
    _compute_segments,
    _download_segment,
    _FallbackToSingleError,
    _probe_url,
    _ProbeResult,
    _Segment,
)
from chroot_distro.helpers.tar_extract import extract_tar_to_rootfs
from chroot_distro.message import warn
from chroot_distro.progress import REDRAW_THRESHOLD_BYTES, AggregateByteProgress, clear_bar, draw_bytes_bar

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
    if isinstance(exc, urllib.error.HTTPError):
        # Only retry on 5xx (server-side) errors; 4xx are permanent.
        return exc.code >= 500
    if isinstance(exc, _RETRYABLE):
        return True
    if isinstance(exc, urllib.error.URLError):
        # The inner reason is usually an ssl.SSLError or OSError.
        return isinstance(exc.reason, _RETRYABLE)
    return False


def _probe_blob(url: str, headers: dict[str, str]) -> _ProbeResult | None:
    """Send HEAD (or fallback GET Range:0-0) to discover size + Range support.

    Uses ``auth_opener()`` so that registry auth tokens and cross-host
    redirect stripping are handled correctly.

    Returns *None* on any network error so the caller can fall back silently.
    """
    opener = auth_opener()
    open_fn = functools.partial(opener.open, timeout=_SOCKET_TIMEOUT)
    return _probe_url(url, headers, open_fn=open_fn)


def download_blob(
    repo: str,
    digest: str,
    token: str,
    registry: str = "",
    *,
    byte_progress: AggregateByteProgress | None = None,
    abort_event: threading.Event | None = None,
    connections: int = 1,
) -> str:
    """Download a blob to the layer cache; return the local file path.

    Streams the bytes through sha256 and verifies the result against the
    expected *digest* before promoting the .tmp file.

    Retries up to ``_MAX_RETRIES`` times on transient network / SSL
    failures with exponential backoff.
    """
    dest = layer_cache_path(digest)
    if os.path.isfile(dest):
        return dest

    if ":" not in digest:
        raise RuntimeError(f"Malformed layer digest '{digest}'.")
    algo, expected_hex = digest.split(":", 1)
    if algo.lower() != "sha256":
        raise RuntimeError(f"Unsupported layer digest algorithm '{algo}' (only sha256 is supported).")

    base = registry_base_url(registry)
    url = f"{base}/v2/{repo}/blobs/{digest}"

    if connections > 1:
        chunks_meta_path = f"{dest}.chunks.json"
        segments = None
        try:
            probe_headers = {**_ua()}
            if token:
                probe_headers["Authorization"] = f"Bearer {token}"
            probe = _probe_blob(url, probe_headers)

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
                    except Exception:
                        pass

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
                    except Exception:
                        pass

                if len(segments) == 1:
                    raise _FallbackToSingleError

                # Pre-fill byte progress with already downloaded bytes
                if byte_progress:
                    already_downloaded = 0
                    for seg in segments:
                        if os.path.isfile(seg.tmp_path):
                            already_downloaded += os.path.getsize(seg.tmp_path)
                    if already_downloaded:
                        byte_progress.add(already_downloaded)

                original_parsed = urllib.parse.urlparse(url)
                final_parsed = urllib.parse.urlparse(probe.final_url)
                seg_headers = {**_ua()}
                if token and original_parsed.netloc == final_parsed.netloc:
                    seg_headers["Authorization"] = f"Bearer {token}"

                local_abort = abort_event or threading.Event()
                with ThreadPoolExecutor(max_workers=len(segments)) as pool:
                    futures = {
                        pool.submit(
                            _download_segment,
                            seg,
                            probe.final_url,
                            seg_headers,
                            byte_progress,
                            local_abort,
                        ): seg
                        for seg in segments
                    }
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except KeyboardInterrupt:
                            local_abort.set()
                            pool.shutdown(wait=False, cancel_futures=True)
                            raise
                        except Exception as exc:
                            local_abort.set()
                            pool.shutdown(wait=False, cancel_futures=True)
                            raise _FallbackToSingleError from exc

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
                        with open(tmp, "rb") as fh:
                            for chunk in iter(lambda: fh.read(262144), b""):
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
        except _FallbackToSingleError:
            pass
        except Exception:
            raise

    last_exc: BaseException | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if attempt > 0:
            delay = _RETRY_BACKOFF[min(attempt - 1, len(_RETRY_BACKOFF) - 1)]
            warn(f"Retry {attempt}/{_MAX_RETRIES} in {delay}s (reason: {last_exc})...")
            time.sleep(delay)

        headers = {**_ua()}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        hasher = hashlib.sha256()

        try:
            with atomic_replace(dest) as tmp:
                opener = auth_opener()
                with opener.open(req, timeout=_SOCKET_TIMEOUT) as resp, open(tmp, "wb") as fh:
                    total = int(resp.headers.get("Content-Length", 0))
                    downloaded = 0
                    unsent = 0  # bytes not yet reported to aggregate
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
                actual_hex = hasher.hexdigest()
                if actual_hex != expected_hex.lower():
                    raise RuntimeError(
                        f"Layer integrity check failed for digest '{digest}': "
                        f"expected {expected_hex}, got {actual_hex}."
                    )
        except KeyboardInterrupt:
            if byte_progress is None:
                clear_bar()
            raise
        except BaseException as exc:
            if byte_progress is None:
                clear_bar()
            if _is_retryable(exc) and attempt < _MAX_RETRIES:
                last_exc = exc
                continue
            raise
        else:
            if byte_progress is None:
                clear_bar()
            return dest

    # Should never reach here, but satisfy the type checker.
    raise RuntimeError(  # pragma: no cover
        f"Download failed for '{digest}' after {_MAX_RETRIES} retries."
    )


def apply_layer(layer_path: str, rootfs_dir: str) -> None:
    """Apply one OCI/Docker layer (gzipped tar) onto rootfs_dir."""
    extract_tar_to_rootfs(layer_path, rootfs_dir, handle_whiteouts=True)
