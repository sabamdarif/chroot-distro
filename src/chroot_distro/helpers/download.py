# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The HTTP layer: retry policy, TLS diagnosis, and the segmented downloader.

Everything that fetches bytes over the network shares this module, including the
registry transport, which imports `retry_http` and `is_retryable_http_error` rather
than keeping its own copy, so a plain URL and a registry blob fail the same way.

Only a failure a repeat request could fix is retried. A 4xx other than 408 and 429, a
certificate verification failure, and a plaintext reply to an https:// URL are
deterministic, so they are re-raised at once and the caller turns them into an
explanation instead of the loop burning five attempts on them.

The two TLS failures are told apart on purpose. A peer that speaks TLS with a
certificate this host does not trust is answered with the `--allow-insecure` hint; a
peer not speaking TLS at all is answered with "use the http:// scheme", and OpenSSL's
own handshake reason proves which it is, so no second probe is needed.

Segmentation is earned, never assumed: HEAD first, a `Range: bytes=0-0` GET when HEAD
is silent about ranges or answers 405, and segments only when Range works *and* the
length is known. `MIN_SEGMENT_BYTES` keeps a small file whole, and a split that yields
one segment raises `_FallbackToSingleError`. Every incompatibility falls back to a
single connection rather than failing the download. Range requests always send
`Accept-Encoding: identity`, because a compressed body makes byte offsets meaningless.

An interrupted download resumes: `.chunkN.tmp` files plus a `.chunks.json` split that
is only reused when it matches the probed length, each segment restarting at its own
file size and reconnecting on its own up to `_MAX_RECONNECTIONS`. Both paths publish
through `atomic_replace`, so a partial body never appears under the destination name.

Ctrl+C is the subtle part. `_LiveResponses.close_all` shuts the socket down instead of
closing the response, because `HTTPResponse.close()` from a signal handler deadlocks
against the buffer lock a worker blocked in `read()` holds at the C level. Every retry
loop also re-checks the abort event before opening a connection: a force-closed socket
surfaces as a retryable OSError, and the loop would otherwise reconnect straight past
the interrupt.
"""

import contextlib
import functools
import hashlib
import json
import logging
import os
import shutil
import signal
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
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

log = logging.getLogger(__name__)

__all__ = (
    "_LiveResponses",
    "certificate_error_msg",
    "download_file",
    "insecure_ssl_context",
    "is_cert_verification_error",
    "is_plaintext_http_tls_error",
    "is_retryable_http_error",
    "retry_http",
    "sha256_file",
)


def insecure_ssl_context() -> ssl.SSLContext:
    """Return an SSL context that skips certificate and hostname checks.

    Used only when the caller explicitly opts in via ``--allow-insecure``,
    so an HTTPS endpoint with an untrusted/expired/self-signed certificate
    (or a hostname mismatch) can still be reached. This disables the
    protection TLS provides against impersonation, and is never the default.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def is_cert_verification_error(exc: urllib.error.URLError) -> bool:
    """Return True if *exc* is a TLS certificate verification failure.

    Covers an untrusted CA, an expired or self-signed certificate, and a
    hostname mismatch: the server *does* speak TLS, but its
    certificate is not trusted. Distinct from is_plaintext_http_tls_error,
    which means the peer is not speaking TLS at all.
    """
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    return isinstance(reason, ssl.SSLError) and getattr(reason, "reason", None) == "CERTIFICATE_VERIFY_FAILED"


def certificate_error_msg(target: str) -> str:
    """Return the error shown when *target* presents an untrusted certificate."""
    return (
        f"TLS certificate verification failed for '{target}': the server's "
        f"certificate is untrusted, expired, self-signed, or issued for a "
        f"different hostname. If you trust this endpoint, re-run with "
        f"'--allow-insecure' to skip certificate verification."
    )


# OpenSSL handshake-failure reasons that mean the peer answered our TLS
# ClientHello with plaintext bytes, the signature of a server that only
# speaks plain HTTP reached over an https:// URL. WRONG_VERSION_NUMBER is what
# modern OpenSSL reports; the others cover older or edge builds. These are
# *not* emitted for genuine TLS problems (expired/untrusted cert,
# protocol-version mismatch), so matching them does not misclassify a real
# HTTPS endpoint.
_PLAINTEXT_HTTP_TLS_REASONS = frozenset(
    {
        "WRONG_VERSION_NUMBER",
        "UNKNOWN_PROTOCOL",
        "HTTP_REQUEST",
    }
)


def is_plaintext_http_tls_error(exc: urllib.error.URLError) -> bool:
    """Return True if *exc* is a TLS handshake failure caused by the peer
    replying with plaintext HTTP rather than a genuine TLS error.

    ``urlopen`` of an https:// URL against a server that only speaks plain
    HTTP raises ``URLError`` whose ``reason`` is an ``ssl.SSLError`` with a
    telltale reason string (e.g. WRONG_VERSION_NUMBER). That alone proves the
    peer is HTTP-only, so no second network probe is needed. Shared by the
    Docker registry transport and the generic URL downloader.
    """
    reason = getattr(exc, "reason", None)
    if not isinstance(reason, ssl.SSLError):
        return False
    return (getattr(reason, "reason", None) or "") in _PLAINTEXT_HTTP_TLS_REASONS


def is_retryable_http_error(exc: BaseException) -> bool:
    """Return True if a failed HTTP request is worth retrying.

    Deterministic failures are not retried, since they cannot succeed on a repeat
    request: an HTTP client error (4xx, except 408 Request Timeout and 429 Too
    Many Requests, which mean "retry later"), a TLS certificate verification
    failure, or a plaintext-HTTP reply to an https:// URL. Everything else
    (5xx server errors, connection resets, timeouts, DNS failures) is treated
    as transient and retried.
    """
    import http.client

    if isinstance(exc, urllib.error.HTTPError):
        return not (400 <= exc.code < 500 and exc.code not in (408, 429))
    if isinstance(exc, urllib.error.URLError):
        return not (is_cert_verification_error(exc) or is_plaintext_http_tls_error(exc))
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return False
    return isinstance(exc, (OSError, ssl.SSLError, http.client.HTTPException))


def retry_http(
    operation,
    *,
    what: str,
    max_retries: int = 5,
    retry_delay: float = 5,
    abort_event: "threading.Event | None" = None,
):
    """Run *operation* (a zero-arg callable performing one HTTP request),
    retrying transient failures with a delay and a logged notice.

    This is the single retry policy shared by the plain URL downloader and the
    Docker/OCI registry transport, so both behave identically. A deterministic
    failure (see is_retryable_http_error) is re-raised immediately, without
    retrying or logging, so the caller can translate it into a meaningful
    message. The original exception is likewise re-raised once every attempt is
    spent. *what* is a short label for the retry log line.

    When *abort_event* is given, an abort (Ctrl+C) is honoured between
    attempts and during the retry delay: a force-closed socket surfaces as a
    retryable OSError, and without this check the loop would sleep and then
    open a brand-new connection after the user already cancelled.
    """
    for attempt in range(max_retries):
        if abort_event is not None and abort_event.is_set():
            raise KeyboardInterrupt
        try:
            return operation()
        except KeyboardInterrupt:
            raise
        except (urllib.error.URLError, OSError) as exc:
            if abort_event is not None and abort_event.is_set():
                raise KeyboardInterrupt from exc
            if not is_retryable_http_error(exc) or attempt >= max_retries - 1:
                raise
            log_info(f"{what}: attempt {attempt + 1}/{max_retries} failed ({exc}); retrying in {retry_delay}s...")
            if abort_event is not None:
                _interruptible_sleep(retry_delay, abort_event)
            else:
                time.sleep(retry_delay)
    return None


_READ_CHUNK = 262144  # 256 KiB
_SOCKET_TIMEOUT = 30  # seconds, so a stalled read() cannot pin a thread forever

# Outer reconnection cap for one chunk; each reconnection attempt itself
# retries up to _max_retries times internally.
_MAX_RECONNECTIONS = 10

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
    return is_retryable_http_error(exc)


def _get_max_retries() -> int:
    """Return the configured max retry count (reads once per call)."""
    from chroot_distro.constants import download_max_retries

    return download_max_retries()


def _get_retry_delays(max_retries: int) -> tuple[float, ...]:
    """Generate exponential backoff delays for *max_retries* attempts."""
    return tuple(min(2**i, 30) for i in range(max_retries))


@dataclass(frozen=True)
class _ProbeResult:
    """Result of probing a URL for Range support.

    *content_length* is 0 when the server did not report one, *final_url* is
    the URL after redirects.
    """

    content_length: int
    final_url: str
    range_ok: bool


@dataclass(frozen=True)
class _Segment:
    """One byte-range slice of a segmented download, *start* and *end* inclusive."""

    index: int
    start: int
    end: int
    tmp_path: str


class _RangeNotSupportedError(Exception):
    """Server responded 200 instead of 206 to a Range request."""


class _FallbackToSingleError(Exception):
    """Signal to retry the whole download as a single connection."""


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
            resp.read(1)
            if resp.status == 206:
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

    1. **HEAD**, fast and with no body. If the response contains
       ``Accept-Ranges: bytes`` we're done.
    2. **GET Range: bytes=0-0**, sent when HEAD succeeds but omits
       ``Accept-Ranges`` (common on CDNs), *or* when HEAD returns 405.
       A 206 reply proves Range support; a 200 reply means no support.

    *open_fn* defaults to ``urllib.request.urlopen`` but can be replaced
    (e.g. with ``auth_opener().open``) for authenticated registries.

    Returns *None* on any network error so the caller can fall back.
    """
    if open_fn is None:
        open_fn = functools.partial(urllib.request.urlopen, timeout=_SOCKET_TIMEOUT)

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
                return _ProbeResult(
                    content_length=content_length,
                    final_url=final_url,
                    range_ok=False,
                )
            need_range_probe = content_length > 0
            if not need_range_probe:
                return _ProbeResult(
                    content_length=content_length,
                    final_url=final_url,
                    range_ok=False,
                )
    except urllib.error.HTTPError as exc:
        if exc.code != 405:
            return None
        need_range_probe = True
    except (OSError, urllib.error.URLError):
        return None

    if need_range_probe:
        return _range_probe(url, headers, open_fn)

    return None  # pragma: no cover


def _probe_server(url: str, headers: dict[str, str], insecure: bool = False) -> "_ProbeResult | None":
    """Send HEAD (or fallback GET Range:0-0) to discover size + Range support.

    Returns *None* on any network error so the caller can fall back silently.
    """
    if insecure:
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=insecure_ssl_context()))
        open_fn = functools.partial(op.open, timeout=_SOCKET_TIMEOUT)
    else:
        open_fn = None
    return _probe_url(url, headers, open_fn=open_fn)


def _compute_segments(total: int, n: int, dest: str) -> list[_Segment]:
    """Split *total* bytes into up to *n* non-overlapping segments.

    Enforces ``MIN_SEGMENT_BYTES``, so the actual segment count may be less
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


def _interruptible_sleep(seconds: float, abort_event: threading.Event) -> None:
    """Sleep for *seconds* but wake up early if *abort_event* is set."""
    remaining = seconds
    while remaining > 0:
        if abort_event.is_set():
            raise KeyboardInterrupt
        step = min(remaining, 0.5)
        time.sleep(step)
        remaining -= step


def _response_socket(resp) -> "socket.socket | None":
    """Return the underlying socket of an ``http.client.HTTPResponse``.

    ``resp.fp`` is a BufferedReader over ``socket.SocketIO``; the SocketIO
    keeps the real socket in ``_sock``. Returns None when the response is
    already closed or the private layout is unavailable.
    """
    try:
        fp = resp.fp
        if fp is None:
            return None
        raw = getattr(fp, "raw", None)
        sock = getattr(raw, "_sock", None)
        return sock if isinstance(sock, socket.socket) else None
    except (AttributeError, ValueError):
        return None


@dataclass
class _LiveResponses:
    """Lock-guarded registry of in-flight responses so an aborting thread can
    force-close a socket that a worker is blocked reading from.

    ``close_all()`` must be safe to call from a SIGINT handler on the main
    thread while worker threads sit inside ``resp.read()``. Calling
    ``resp.close()`` there deadlocks: HTTPResponse.close() closes its
    BufferedReader, which needs the same internal buffer lock the blocked
    reader thread is holding, uninterruptibly, at the C level. Instead we
    ``shutdown(2)`` the underlying socket, which takes no Python-level lock
    and makes the blocked ``recv()`` return immediately.
    """

    lock: threading.Lock
    responses: set

    def add(self, resp) -> None:
        with self.lock:
            self.responses.add(resp)

    def discard(self, resp) -> None:
        with self.lock:
            self.responses.discard(resp)

    def close_all(self) -> None:
        with self.lock:
            for resp in list(self.responses):
                sock = _response_socket(resp)
                if sock is not None:
                    with contextlib.suppress(Exception):
                        sock.shutdown(socket.SHUT_RDWR)
                else:
                    # No live socket to shut down: close() cannot block.
                    with contextlib.suppress(Exception):
                        resp.close()
            self.responses.clear()


def _download_segment(
    seg: _Segment,
    url: str,
    ua_headers: dict[str, str],
    aggregate: "AggregateByteProgress | None",
    abort_event: threading.Event,
    bucket: "TokenBucket | None" = None,
    live_responses: "_LiveResponses | None" = None,
    insecure: bool = False,
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
    if insecure:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=insecure_ssl_context()))
    else:
        opener = urllib.request.build_opener()

    reconnections = 0
    while reconnections <= _MAX_RECONNECTIONS:
        for attempt in range(max_retries + 1):
            try:
                # Never open a new connection after the user aborted: a
                # force-closed socket surfaces as a retryable OSError, and
                # this loop would otherwise reconnect right past the Ctrl+C.
                if abort_event.is_set():
                    raise KeyboardInterrupt
                start_pos = seg.start + downloaded
                headers = {
                    **ua_headers,
                    "Range": f"bytes={start_pos}-{seg.end}",
                    "Accept-Encoding": "identity",  # critical: no gzip, breaks range math
                }
                req = urllib.request.Request(url, headers=headers)
                mode = "ab" if downloaded > 0 else "wb"
                with opener.open(req, timeout=_SOCKET_TIMEOUT) as resp, open(seg.tmp_path, mode) as fh:
                    if live_responses is not None:
                        live_responses.add(resp)
                    # If an abort raced the connection open, stop immediately.
                    if abort_event.is_set():
                        raise KeyboardInterrupt
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
                    if aggregate and unsent:
                        aggregate.add(unsent)
                    fh.flush()
                    os.fsync(fh.fileno())
                if live_responses is not None:
                    live_responses.discard(resp)
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
                if abort_event.is_set():
                    raise KeyboardInterrupt from exc
                if _is_retriable(exc) and attempt < max_retries:
                    _interruptible_sleep(retry_delays[attempt], abort_event)
                    if os.path.isfile(seg.tmp_path):
                        downloaded = os.path.getsize(seg.tmp_path)
                    continue
                # Retries exhausted: reconnect and resume from what is on
                # disk rather than failing the whole segment.
                if os.path.isfile(seg.tmp_path):
                    downloaded = os.path.getsize(seg.tmp_path)
                if downloaded >= expected:
                    return
                reconnections += 1
                if reconnections > _MAX_RECONNECTIONS:
                    raise
                opener = urllib.request.build_opener()
                break  # re-enter the reconnection loop

    raise RuntimeError(
        f"Segment {seg.index}: exhausted {_MAX_RECONNECTIONS} reconnection attempts "
        f"(downloaded {downloaded}/{expected} bytes)"
    )


def _concat_chunks(segments: list[_Segment], dest: str) -> None:
    """Concatenate segment temp files in order into *dest* atomically."""
    with atomic_replace(dest) as tmp, open(tmp, "wb") as out:
        for seg in sorted(segments, key=lambda s: s.index):
            with open(seg.tmp_path, "rb") as inp:
                shutil.copyfileobj(inp, out, length=1 << 20)
        out.flush()
        os.fsync(out.fileno())


def _concat_chunks_inplace(segments: list[_Segment], dest: str) -> None:
    """Chunk-0 append assembly.

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
                    buf = inp.read(1 << 15)  # 32 KiB
                    if not buf:
                        break
                    out.write(buf)
            os.remove(seg.tmp_path)
        out.flush()
        os.fsync(out.fileno())
    os.replace(base, dest)


def _download_multi(
    url: str,
    dest: str,
    probe: _ProbeResult,
    connections: int,
    bucket: "TokenBucket | None" = None,
    insecure: bool = False,
) -> None:
    """Download *url* to *dest* using multiple parallel Range connections."""
    chunks_meta_path = f"{dest}.chunks.json"
    segments = None

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
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            log.debug("Failed to load chunks metadata from %s: %s", chunks_meta_path, exc)

    if not segments:
        # A previous run may have split into more segments than this one, so
        # sweep a few indices past the current count.
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
        except (OSError, ValueError) as exc:
            log.warning("Failed to save chunk download metadata to %s: %s", chunks_meta_path, exc)

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
    live_responses = _LiveResponses(lock=threading.Lock(), responses=set())
    ua = _ua_headers()

    def _on_sigint(_signum, _frame):
        abort_event.set()
        live_responses.close_all()
        raise KeyboardInterrupt

    prev_sigint = signal.getsignal(signal.SIGINT)

    if already_downloaded:
        log_info(
            f"Resuming download of {fmt_size(total)} (already downloaded {fmt_size(already_downloaded)}) in {len(segments)} segments..."
        )
    else:
        log_info(f"Downloading {fmt_size(total)} in {len(segments)} segments ({len(segments)} connections)...")

    success = False
    with contextlib.suppress(ValueError):
        # signal.signal only works on the main thread; suppress if not.
        signal.signal(signal.SIGINT, _on_sigint)
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
                    live_responses,
                    insecure=insecure,
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
            live_responses.close_all()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        except Exception:
            abort_event.set()
            live_responses.close_all()
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
        with contextlib.suppress(ValueError):
            signal.signal(signal.SIGINT, prev_sigint)
        aggregate.clear()
        if success:
            for seg in segments:
                with contextlib.suppress(OSError):
                    os.remove(seg.tmp_path)
            with contextlib.suppress(OSError):
                os.remove(chunks_meta_path)


def _download_single(
    url: str,
    dest: str,
    bucket: "TokenBucket | None" = None,
    insecure: bool = False,
) -> None:
    """Download *url* to *dest* with a single connection (original path)."""
    max_retries = _get_max_retries()
    retry_delays = _get_retry_delays(max_retries)

    req = urllib.request.Request(url, headers=_ua_headers())
    last_exc: BaseException | None = None
    abort_event = threading.Event()

    def _on_sigint(_signum, _frame):
        abort_event.set()
        raise KeyboardInterrupt

    prev_sigint = signal.getsignal(signal.SIGINT)
    with contextlib.suppress(ValueError):
        signal.signal(signal.SIGINT, _on_sigint)
    context = insecure_ssl_context() if insecure else None
    try:
        return _download_single_loop(
            req, dest, bucket, max_retries, retry_delays, abort_event, last_exc, context=context, insecure=insecure
        )
    finally:
        with contextlib.suppress(ValueError):
            signal.signal(signal.SIGINT, prev_sigint)


def _download_single_loop(
    req: urllib.request.Request,
    dest: str,
    bucket: "TokenBucket | None",
    max_retries: int,
    retry_delays: tuple[float, ...],
    abort_event: threading.Event,
    last_exc: BaseException | None,
    context: ssl.SSLContext | None = None,
    insecure: bool = False,
) -> None:
    url = req.full_url
    for attempt in range(max_retries + 1):
        if attempt > 0:
            delay = retry_delays[attempt - 1]
            warn(f"Retry {attempt}/{max_retries} in {delay}s (reason: {last_exc})...")
            _interruptible_sleep(delay, abort_event)

        try:
            with (
                atomic_replace(dest) as tmp,
                urllib.request.urlopen(req, context=context, timeout=_SOCKET_TIMEOUT) as resp,
                open(tmp, "wb") as fh,
            ):
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
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

            host = urllib.parse.urlparse(url).netloc or url
            if isinstance(exc, urllib.error.URLError):
                if not insecure and is_cert_verification_error(exc):
                    raise RuntimeError(certificate_error_msg(host)) from exc
                if is_plaintext_http_tls_error(exc):
                    raise RuntimeError(
                        f"The URL '{url}' uses HTTPS, but the server at '{host}' "
                        f"responded over plain HTTP (no TLS). If you trust this "
                        f"source, retry with the same URL using the 'http://' "
                        f"scheme instead."
                    ) from exc
            if isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500 and exc.code not in (408, 429):
                raise RuntimeError(f"Cannot download {url}: HTTP {exc.code} {exc.reason}") from exc

            msg()
            log_error("Download failure, please check your network connection.")
            raise RuntimeError(f"Cannot download {url}: {exc}") from exc


def download_file(
    url: str,
    dest: str,
    max_retries: int | None = None,
    retry_delay: float | None = None,
    insecure: bool = False,
) -> None:
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

    rate = download_rate_limit()
    bucket = TokenBucket(rate) if rate > 0 else None

    if connections > 1:
        with loading_line("Connecting..."):
            probe = _probe_server(url, _ua_headers(), insecure=insecure)

        if probe is None:
            log_info("Server probe failed, falling back to single connection.")
        elif not probe.range_ok:
            log_info("Server does not support Range requests, using single connection.")
        elif probe.content_length <= 0:
            log_info("Unknown content length, using single connection.")
        else:
            log_info(f"Range supported, content length {fmt_size(probe.content_length)}. Using segmented download.")
            try:
                _download_multi(url, dest, probe, connections, bucket, insecure=insecure)
                return
            except _FallbackToSingleError:
                log_info("Segments too small for splitting, falling back to single connection.")
            except KeyboardInterrupt:
                clear_bar()
                raise
            except Exception as exc:
                clear_bar()
                host = urllib.parse.urlparse(url).netloc or url
                if isinstance(exc, urllib.error.URLError):
                    if not insecure and is_cert_verification_error(exc):
                        raise RuntimeError(certificate_error_msg(host)) from exc
                    if is_plaintext_http_tls_error(exc):
                        raise RuntimeError(
                            f"The URL '{url}' uses HTTPS, but the server at '{host}' "
                            f"responded over plain HTTP (no TLS). If you trust this "
                            f"source, retry with the same URL using the 'http://' "
                            f"scheme instead."
                        ) from exc
                if isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500 and exc.code not in (408, 429):
                    raise RuntimeError(f"Cannot download {url}: HTTP {exc.code} {exc.reason}") from exc
                raise RuntimeError(f"Cannot download {url}: {exc}") from exc

    _download_single(url, dest, bucket, insecure=insecure)


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
