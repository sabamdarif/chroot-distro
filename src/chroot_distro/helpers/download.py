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
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.client import HTTPResponse

from chroot_distro.atomic import atomic_replace
from chroot_distro.constants import (
    MIN_SEGMENT_BYTES,
    PROGRAM_NAME,
    PROGRAM_VERSION,
)
from chroot_distro.message import log_error, log_info, msg, warn
from chroot_distro.progress import (
    REDRAW_THRESHOLD_BYTES,
    AggregateByteProgress,
    clear_bar,
    draw_bytes_bar,
    fmt_size,
    loading_line,
)
from chroot_distro.rate_limit import TokenBucket

__all__ = ("download_file", "sha256_file")

_READ_CHUNK = 262144  # 256 KiB — balances syscall overhead vs memory
_SOCKET_TIMEOUT = 30  # seconds — prevents threads from blocking in read() forever

# Maximum number of reconnection attempts for a single chunk (PyLoad §6).
# This is the outer reconnection cap; each reconnection attempt itself
# retries up to _max_retries times internally.
_MAX_RECONNECTIONS = 10

# Transient error types worth retrying.
_TRANSIENT_ERRORS = (
    ssl.SSLError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    TimeoutError,
    OSError,
)


def _ua_headers() -> dict[str, str]:
    return {"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"}


def _is_retriable(exc: BaseException) -> bool:
    """Return True for transient server or connection failures."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    if isinstance(exc, _TRANSIENT_ERRORS):
        return True
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, _TRANSIENT_ERRORS)
    return False


def _get_max_retries() -> int:
    """Return the configured max retry count (reads once per call)."""
    from chroot_distro.constants import download_max_retries

    return download_max_retries()


def _get_retry_delays(max_retries: int) -> tuple[float, ...]:
    """Generate exponential backoff delays for *max_retries* attempts."""
    return tuple(min(2**i, 30) for i in range(max_retries))


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProbeResult:
    """Result of probing a URL for Range support."""

    content_length: int  # total bytes (0 if unknown)
    final_url: str  # URL after redirects
    range_ok: bool  # server supports Accept-Ranges: bytes


@dataclass(frozen=True)
class _Segment:
    """One byte-range slice of a segmented download."""

    index: int
    start: int  # inclusive byte offset
    end: int  # inclusive byte offset
    tmp_path: str  # absolute path to .chunkN.tmp


class _RangeNotSupportedError(Exception):
    """Server responded 200 instead of 206 to a Range request."""


class _FallbackToSingleError(Exception):
    """Signal to retry the whole download as a single connection."""


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


def _range_probe(
    url: str,
    headers: dict[str, str],
    open_fn: "Callable[..., HTTPResponse] | None" = None,
) -> "_ProbeResult | None":
    """Lightweight GET Range:bytes=0-0 probe to test actual Range support.

    Returns a ``_ProbeResult`` or *None* on network error.
    """
    if open_fn is None:
        open_fn = functools.partial(urllib.request.urlopen, timeout=_SOCKET_TIMEOUT)
    try:
        range_headers = {**headers, "Range": "bytes=0-0", "Accept-Encoding": "identity"}
        range_req = urllib.request.Request(url, headers=range_headers)
        with open_fn(range_req) as resp:
            resp.read(1)  # consume minimal body
            if resp.status == 206:
                # Parse Content-Range: bytes 0-0/TOTAL
                cr = resp.headers.get("Content-Range", "")
                total = 0
                if "/" in cr:
                    with contextlib.suppress(ValueError, IndexError):
                        total = int(cr.rsplit("/", 1)[1])
                return _ProbeResult(
                    content_length=total,
                    final_url=resp.url,
                    range_ok=True,
                )
            # Server returned 200 — no range support
            return _ProbeResult(
                content_length=int(resp.headers.get("Content-Length", 0)),
                final_url=resp.url,
                range_ok=False,
            )
    except (OSError, urllib.error.URLError):
        return None


def _probe_url(
    url: str,
    headers: dict[str, str],
    open_fn: "Callable[..., HTTPResponse] | None" = None,
) -> "_ProbeResult | None":
    """Discover file size and Range support for *url*.

    Strategy (two-stage):

    1. **HEAD** — fast, no body.  If the response contains
       ``Accept-Ranges: bytes`` we're done.
    2. **GET Range: bytes=0-0** — sent when HEAD succeeds but omits
       ``Accept-Ranges`` (common on CDNs), *or* when HEAD returns 405.
       A 206 reply proves Range support; a 200 reply means no support.

    *open_fn* defaults to ``urllib.request.urlopen`` but can be replaced
    (e.g. with ``auth_opener().open``) for authenticated registries.

    Returns *None* on any network error so the caller can fall back.
    """
    if open_fn is None:
        open_fn = functools.partial(urllib.request.urlopen, timeout=_SOCKET_TIMEOUT)

    # --- 1st try: HEAD ---
    need_range_probe = False
    try:
        head_req = urllib.request.Request(url, headers=headers, method="HEAD")
        with open_fn(head_req) as resp:
            content_length = int(resp.headers.get("Content-Length", 0))
            accept_ranges = (resp.headers.get("Accept-Ranges", "")).lower()
            final_url = resp.url
            if accept_ranges == "bytes":
                return _ProbeResult(
                    content_length=content_length,
                    final_url=final_url,
                    range_ok=True,
                )
            if accept_ranges == "none":
                # Server explicitly says no ranges.
                return _ProbeResult(
                    content_length=content_length,
                    final_url=final_url,
                    range_ok=False,
                )
            # No Accept-Ranges header — many CDNs omit it but still
            # support Range requests.  Fall through to the GET probe.
            need_range_probe = content_length > 0
            if not need_range_probe:
                return _ProbeResult(
                    content_length=content_length,
                    final_url=final_url,
                    range_ok=False,
                )
    except urllib.error.HTTPError as exc:
        if exc.code != 405:
            return None  # non-405 → give up probing
        need_range_probe = True
    except (OSError, urllib.error.URLError):
        return None

    # --- 2nd try: GET Range: bytes=0-0 ---
    if need_range_probe:
        return _range_probe(url, headers, open_fn)

    return None  # pragma: no cover


def _probe_server(url: str, headers: dict[str, str]) -> "_ProbeResult | None":
    """Send HEAD (or fallback GET Range:0-0) to discover size + Range support.

    Returns *None* on any network error so the caller can fall back silently.
    """
    return _probe_url(url, headers)


# ---------------------------------------------------------------------------
# Segment computation
# ---------------------------------------------------------------------------


def _compute_segments(total: int, n: int, dest: str) -> list[_Segment]:
    """Split *total* bytes into up to *n* non-overlapping segments.

    Enforces ``MIN_SEGMENT_BYTES`` — the actual segment count may be less
    than *n* for small files.
    """
    n = min(n, max(1, total // MIN_SEGMENT_BYTES))
    n = max(1, n)
    chunk_size = total // n
    segments: list[_Segment] = []
    for i in range(n):
        start = i * chunk_size
        end = total - 1 if i == n - 1 else (i + 1) * chunk_size - 1
        segments.append(
            _Segment(
                index=i,
                start=start,
                end=end,
                tmp_path=f"{dest}.chunk{i}.tmp",
            )
        )
    return segments


# ---------------------------------------------------------------------------
# Per-segment download (PyLoad §4 + §6 resilience)
# ---------------------------------------------------------------------------


def _interruptible_sleep(seconds: float, abort_event: threading.Event) -> None:
    """Sleep for *seconds* but wake up early if *abort_event* is set."""
    remaining = seconds
    while remaining > 0:
        if abort_event.is_set():
            raise KeyboardInterrupt
        step = min(remaining, 0.5)
        time.sleep(step)
        remaining -= step


def _download_segment(
    seg: _Segment,
    url: str,
    ua_headers: dict[str, str],
    aggregate: "AggregateByteProgress | None",
    abort_event: threading.Event,
    bucket: "TokenBucket | None" = None,
) -> None:
    """Download one byte-range segment to *seg.tmp_path*.

    Implements PyLoad §6 per-chunk reconnection: if the connection drops
    mid-stream, the segment resumes from where it left off (adjusting the
    ``Range`` header) rather than failing the entire multi-segment download.

    Falls back via ``_RangeNotSupportedError`` if the server responds 200
    instead of 206, or ``416 Range Not Satisfiable``.

    Raises ``KeyboardInterrupt`` if *abort_event* is set.
    """
    max_retries = _get_max_retries()
    retry_delays = _get_retry_delays(max_retries)

    downloaded = 0
    if os.path.isfile(seg.tmp_path):
        downloaded = os.path.getsize(seg.tmp_path)

    expected = seg.end - seg.start + 1
    if downloaded >= expected:
        return

    # Each thread gets its own opener to avoid urllib's internal
    # connection serialisation when sharing the default global opener.
    opener = urllib.request.build_opener()

    reconnections = 0
    while reconnections <= _MAX_RECONNECTIONS:
        for attempt in range(max_retries + 1):
            try:
                start_pos = seg.start + downloaded
                headers = {
                    **ua_headers,
                    "Range": f"bytes={start_pos}-{seg.end}",
                    "Accept-Encoding": "identity",  # critical: no gzip, breaks range math
                }
                req = urllib.request.Request(url, headers=headers)
                mode = "ab" if downloaded > 0 else "wb"
                with opener.open(req, timeout=_SOCKET_TIMEOUT) as resp, open(seg.tmp_path, mode) as fh:
                    # 416 Range Not Satisfiable → server lost range support mid-download
                    if resp.status == 416:
                        raise _RangeNotSupportedError(
                            f"Server returned 416 Range Not Satisfiable for segment {seg.index}"
                        )
                    if resp.status != 206:
                        raise _RangeNotSupportedError(f"Expected 206, got {resp.status}")
                    unsent = 0  # bytes not yet reported to aggregate
                    while True:
                        if abort_event.is_set():
                            raise KeyboardInterrupt
                        chunk = resp.read(_READ_CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
                        downloaded += len(chunk)
                        if bucket:
                            bucket.consume(len(chunk))
                        if aggregate:
                            unsent += len(chunk)
                            if unsent >= REDRAW_THRESHOLD_BYTES:
                                aggregate.add(unsent)
                                unsent = 0
                    # flush remaining unsent bytes
                    if aggregate and unsent:
                        aggregate.add(unsent)
                    fh.flush()
                    os.fsync(fh.fileno())
                # verify size
                actual = os.path.getsize(seg.tmp_path)
                if actual != expected:
                    raise RuntimeError(f"Segment {seg.index}: expected {expected} bytes, got {actual}")
                return
            except _RangeNotSupportedError:
                raise  # not retriable; bubble up immediately
            except urllib.error.HTTPError as exc:
                if exc.code == 416:
                    raise _RangeNotSupportedError(
                        f"Server returned 416 Range Not Satisfiable for segment {seg.index}"
                    ) from exc
                if _is_retriable(exc) and attempt < max_retries:
                    _interruptible_sleep(retry_delays[attempt], abort_event)
                    if os.path.isfile(seg.tmp_path):
                        downloaded = os.path.getsize(seg.tmp_path)
                    continue
                raise
            except KeyboardInterrupt:
                raise
            except BaseException as exc:
                if _is_retriable(exc) and attempt < max_retries:
                    _interruptible_sleep(retry_delays[attempt], abort_event)
                    if os.path.isfile(seg.tmp_path):
                        downloaded = os.path.getsize(seg.tmp_path)
                    continue
                # All retries exhausted for this reconnection attempt.
                # PyLoad §6: reconnect the chunk from where we left off.
                if os.path.isfile(seg.tmp_path):
                    downloaded = os.path.getsize(seg.tmp_path)
                if downloaded >= expected:
                    return  # actually complete
                reconnections += 1
                if reconnections > _MAX_RECONNECTIONS:
                    raise
                # Recreate the opener for a fresh connection
                opener = urllib.request.build_opener()
                break  # break the retry loop, re-enter the reconnection loop

    # Exhausted all reconnection attempts
    raise RuntimeError(
        f"Segment {seg.index}: exhausted {_MAX_RECONNECTIONS} reconnection attempts "
        f"(downloaded {downloaded}/{expected} bytes)"
    )


# ---------------------------------------------------------------------------
# Chunk concatenation
# ---------------------------------------------------------------------------


def _concat_chunks(segments: list[_Segment], dest: str) -> None:
    """Concatenate segment temp files in order into *dest* atomically."""
    with atomic_replace(dest) as tmp, open(tmp, "wb") as out:
        for seg in sorted(segments, key=lambda s: s.index):
            with open(seg.tmp_path, "rb") as inp:
                shutil.copyfileobj(inp, out, length=1 << 20)
        out.flush()
        os.fsync(out.fileno())


def _concat_chunks_inplace(segments: list[_Segment], dest: str) -> None:
    """PyLoad §4.5 chunk-0 append assembly.

    Appends subsequent chunks into chunk0 in-place, then renames to *dest*.
    Saves disk space (no full-size temp copy) but is less crash-safe than
    :func:`_concat_chunks`.
    """
    ordered = sorted(segments, key=lambda s: s.index)
    base = ordered[0].tmp_path
    with open(base, "ab") as out:
        for seg in ordered[1:]:
            with open(seg.tmp_path, "rb") as inp:
                while True:
                    buf = inp.read(1 << 15)  # 32 KiB buffers per PyLoad
                    if not buf:
                        break
                    out.write(buf)
            os.remove(seg.tmp_path)
        out.flush()
        os.fsync(out.fileno())
    os.replace(base, dest)


# ---------------------------------------------------------------------------
# Multi-connection orchestrator
# ---------------------------------------------------------------------------


def _download_multi(
    url: str,
    dest: str,
    probe: _ProbeResult,
    connections: int,
    bucket: "TokenBucket | None" = None,
) -> None:
    """Download *url* to *dest* using multiple parallel Range connections."""
    chunks_meta_path = f"{dest}.chunks.json"
    segments = None

    # Try to load existing chunk metadata
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
        # Clean up any potential stale chunk files
        for i in range(connections + 5):
            with contextlib.suppress(OSError):
                os.remove(f"{dest}.chunk{i}.tmp")
        with contextlib.suppress(OSError):
            os.remove(chunks_meta_path)

        segments = _compute_segments(probe.content_length, connections, dest)
        if len(segments) == 1:
            raise _FallbackToSingleError

        # Save metadata
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

    total = probe.content_length
    aggregate = AggregateByteProgress(total, label="download")

    already_downloaded = 0
    for seg in segments:
        if os.path.isfile(seg.tmp_path):
            already_downloaded += os.path.getsize(seg.tmp_path)
    if already_downloaded:
        aggregate.add(already_downloaded)

    abort_event = threading.Event()
    ua = _ua_headers()

    if already_downloaded:
        log_info(
            f"Resuming download of {fmt_size(total)} (already downloaded {fmt_size(already_downloaded)}) in {len(segments)} segments..."
        )
    else:
        log_info(f"Downloading {fmt_size(total)} in {len(segments)} segments ({len(segments)} connections)...")

    success = False
    try:
        pool = ThreadPoolExecutor(max_workers=len(segments))
        try:
            futures = {
                pool.submit(
                    _download_segment,
                    seg,
                    probe.final_url,
                    ua,
                    aggregate,
                    abort_event,
                    bucket,
                ): seg
                for seg in segments
            }
            for future in as_completed(futures):
                future.result()
        except _RangeNotSupportedError as exc:
            abort_event.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise _FallbackToSingleError from exc
        except KeyboardInterrupt:
            abort_event.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        except Exception:
            abort_event.set()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

        clear_bar()
        log_info("Assembling segments...")
        _concat_chunks(segments, dest)
        log_info(f"Finished downloading ({fmt_size(total)}).")
        success = True

    finally:
        aggregate.clear()
        if success:
            for seg in segments:
                with contextlib.suppress(OSError):
                    os.remove(seg.tmp_path)
            with contextlib.suppress(OSError):
                os.remove(chunks_meta_path)


# ---------------------------------------------------------------------------
# Single-connection download (original logic, renamed)
# ---------------------------------------------------------------------------


def _download_single(
    url: str,
    dest: str,
    bucket: "TokenBucket | None" = None,
) -> None:
    """Download *url* to *dest* with a single connection (original path)."""
    max_retries = _get_max_retries()
    retry_delays = _get_retry_delays(max_retries)

    req = urllib.request.Request(url, headers=_ua_headers())
    last_exc: BaseException | None = None
    for attempt in range(max_retries + 1):
        if attempt > 0:
            delay = retry_delays[attempt - 1]
            warn(f"Retry {attempt}/{max_retries} in {delay}s (reason: {last_exc})...")
            time.sleep(delay)

        try:
            with (
                atomic_replace(dest) as tmp,
                urllib.request.urlopen(req, timeout=_SOCKET_TIMEOUT) as resp,
                open(tmp, "wb") as fh,
            ):
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                # Draw initial 0% bar immediately
                draw_bytes_bar(0, total, noun="downloaded")
                last_speed_time = time.monotonic()
                last_speed_bytes = 0
                speed = 0.0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if bucket:
                        bucket.consume(len(chunk))
                    # Update speed every ~0.5s
                    now = time.monotonic()
                    dt = now - last_speed_time
                    if dt >= 0.5:
                        speed = (downloaded - last_speed_bytes) / dt
                        last_speed_bytes = downloaded
                        last_speed_time = now
                    draw_bytes_bar(downloaded, total, noun="downloaded", speed=speed)
                fh.flush()
                os.fsync(fh.fileno())
            clear_bar()
            log_info(f"Finished downloading ({fmt_size(downloaded)}).")
            return
        except KeyboardInterrupt:
            clear_bar()
            raise
        except BaseException as exc:
            clear_bar()
            if _is_retriable(exc) and attempt < max_retries:
                last_exc = exc
                continue
            msg()
            log_error("Download failure, please check your network connection.")
            raise RuntimeError(f"Cannot download {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def download_file(url: str, dest: str) -> None:
    """Download *url* to *dest* with progress output, redirects, and retries.

    Uses multiple parallel Range connections when ``CD_DOWNLOAD_WORKERS > 1``
    and the server advertises ``Accept-Ranges`` support.  Falls back to a
    single connection automatically on any incompatibility.

    Bandwidth can be limited via ``CD_DOWNLOAD_RATE_LIMIT`` (e.g. ``"5M"``
    for 5 MiB/s).  Retry count is configurable via ``CD_DOWNLOAD_MAX_RETRIES``
    (default 3).
    """
    from chroot_distro.constants import download_rate_limit, layer_download_workers

    connections = layer_download_workers()

    # Create a shared rate limiter (0 = unlimited)
    rate = download_rate_limit()
    bucket = TokenBucket(rate) if rate > 0 else None

    if connections > 1:
        # Probe with immediate spinner feedback
        with loading_line("Connecting..."):
            probe = _probe_server(url, _ua_headers())

        if probe is None:
            log_info("Server probe failed, falling back to single connection.")
        elif not probe.range_ok:
            log_info("Server does not support Range requests, using single connection.")
        elif probe.content_length <= 0:
            log_info("Unknown content length, using single connection.")
        else:
            log_info(f"Range supported, content length {fmt_size(probe.content_length)}. Using segmented download.")
            try:
                _download_multi(url, dest, probe, connections, bucket)
                return
            except _FallbackToSingleError:
                log_info("Segments too small for splitting, falling back to single connection.")
            except KeyboardInterrupt:
                clear_bar()
                raise
            except Exception as exc:
                clear_bar()
                raise RuntimeError(f"Cannot download {url}: {exc}") from exc

    # Single-connection fallback
    _download_single(url, dest, bucket)


def sha256_file(path: str) -> str:
    """Compute and return the SHA-256 hex digest of *path*, with a progress bar."""
    h = hashlib.sha256()
    total = os.path.getsize(path)
    processed = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            processed += len(chunk)
            draw_bytes_bar(processed, total, noun="processed")
    clear_bar()
    return h.hexdigest()
