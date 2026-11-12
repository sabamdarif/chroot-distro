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

Every request goes through `http_opener()`, the one place an opener is built: HTTP and
HTTPS and nothing else, with a redirect handler that refuses a step down from HTTPS to
plain HTTP. No manifest, `install <url>` archive or `ADD <url>` file is pinned to a
digest, so a plaintext hop would let whoever sits on it choose what is installed.

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
import datetime
import email.utils
import functools
import hashlib
import http.client
import json
import logging
import math
import os
import re
import shutil
import signal
import socket
import ssl
import threading
import time
import typing
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
from chroot_distro.message import log_error, log_info, msg, quote_path, warn
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
    "MAX_METADATA_BYTES",
    "MAX_RETRY_AFTER",
    "NETWORK_ERRORS",
    "NETWORK_TIMEOUT",
    "IncompleteResponse",
    "RedirectPolicyHandler",
    "RedirectRefused",
    "_LiveResponses",
    "certificate_error_msg",
    "check_redirect",
    "declared_length",
    "download_file",
    "http_opener",
    "insecure_ssl_context",
    "is_cert_verification_error",
    "is_plaintext_http_tls_error",
    "is_retryable_http_error",
    "require_complete_body",
    "retry_after",
    "retry_http",
    "sha256_file",
)


# What a failed HTTP request raises, in one name. urllib wraps what it can
# into URLError (itself an OSError), and a socket failure is an OSError
# outright, but http.client raises its own family for a response that is
# malformed or cut short: a chunked body whose peer disappears mid-chunk
# raises IncompleteRead, which is not an OSError.
NETWORK_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException)

# How large a metadata response may be before it is refused. Manifests,
# manifest indexes, image configs, token grants and search pages are all
# small documents and none of them streams.
MAX_METADATA_BYTES = 16 * 1024 * 1024


class IncompleteResponse(http.client.HTTPException):
    """A response body that ended before the length it declared.

    Raised by require_complete_body(). An HTTPException so it travels with
    the rest of them, caught by every net and retried by retry_http.
    """


def declared_length(resp) -> int:
    """The body length *resp* declares, or 0 when it declares none.

    A header is a string the server chose, so an unparsable length answers
    the same way http.client itself treats it: as absent.
    """
    try:
        value = int(resp.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


def require_complete_body(received: int, declared: int, what: str = "") -> None:
    """Raise IncompleteResponse when less arrived than *declared*.

    A cut Content-Length body raises nothing on its own, so the short bytes
    were simply what the caller got. Callers pass the length they already
    read; one that deliberately reads part of a body must not call this.
    """
    if declared and received < declared:
        prefix = f"{what}: " if what else ""
        raise IncompleteResponse(f"{prefix}the response ended after {received} of {declared} bytes.")


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


# How long a request waits for a peer that says nothing. It is a socket
# timeout, so it bounds each step (connect, handshake, every send, every
# read) and not the whole transfer. Two minutes without a byte is a dead
# peer rather than a slow one, and long enough for a mobile link to come
# back from a gap.
NETWORK_TIMEOUT = 120.0

# Stands for "the caller named no timeout" in _Opener.open(), so the
# default is looked up when the request is made.
_DEFAULT_TIMEOUT = object()


class _Opener(urllib.request.OpenerDirector):
    """An OpenerDirector that gives every request a timeout by default.

    urllib's default is the socket module's, which is none at all, so a
    peer that accepted the connection and then said nothing blocked for
    good and retry_http never got to act.
    """

    def open(self, fullurl, data=None, timeout=_DEFAULT_TIMEOUT):
        if timeout is _DEFAULT_TIMEOUT:
            timeout = NETWORK_TIMEOUT
        return super().open(fullurl, data, timeout)


class RedirectRefused(http.client.HTTPException):
    """A redirect this program will not follow.

    Raised by check_redirect(). An HTTPException so every net catches it
    through NETWORK_ERRORS, and one retry_http never repeats, since the
    server gives the same answer every time. *plaintext* is True when the
    refusal is a step down from HTTPS to plain HTTP, the one kind insecure
    transport permits.
    """

    def __init__(self, message: str, plaintext: bool = False):
        super().__init__(message)
        self.plaintext = plaintext


# The schemes a redirect may lead to: the same two every URL this program
# accepts from the user is held to.
_FOLLOWED_SCHEMES = ("http", "https")


def check_redirect(from_url: str, location: str, *, allow_plaintext: bool = False) -> None:
    """Raise RedirectRefused unless a redirect to *location* may be followed.

    *location* is the header as the server sent it, relative or not, and is
    resolved against *from_url* the way the redirect itself will be. A target
    that is not a URL, any scheme but http or https, one naming no host, and
    (unless *allow_plaintext*) a step down from HTTPS to plain HTTP are all
    refusals. Nothing pins a tag's manifest, an `install <url>` archive or an
    `ADD <url>` file to a digest, so whoever sat on the plaintext hop decides
    what is installed or built.
    """
    try:
        target = urllib.parse.urljoin(from_url, location)
        src = urllib.parse.urlsplit(from_url)
        dst = urllib.parse.urlsplit(target)
    except ValueError:
        raise RedirectRefused(
            f"Refusing to follow a redirect from '{quote_path(from_url)}': "
            f"its target '{quote_path(location)}' is not a valid URL."
        ) from None
    if dst.scheme not in _FOLLOWED_SCHEMES or not dst.hostname:
        raise RedirectRefused(
            f"Refusing to follow a redirect from '{quote_path(from_url)}' "
            f"to '{quote_path(target)}': only http:// and https:// URLs "
            f"naming a host are followed."
        )
    if src.scheme == "https" and dst.scheme == "http" and not allow_plaintext:
        raise RedirectRefused(
            f"Refusing to follow a redirect from '{quote_path(from_url)}' "
            f"to '{quote_path(target)}': it leaves HTTPS for plain HTTP, "
            f"so what arrives would no longer be protected by TLS.",
            plaintext=True,
        )


class RedirectPolicyHandler(urllib.request.HTTPRedirectHandler):
    """urllib's redirect handler, following only what check_redirect allows.

    The check runs twice on purpose. http_error_30x runs it on the raw
    Location before urllib's own handling touches it, because that handling
    answers a malformed header with a bare ValueError and a scheme it
    dislikes with an HTTPError whose 3xx code retry_http reads as transient.
    redirect_request runs it on the absolute URL the new request is built
    for, which is what a subclass calls directly.
    """

    def __init__(self, allow_plaintext: bool = False):
        super().__init__()
        self.allow_plaintext = allow_plaintext

    def _refuse(self, fp, from_url: str, location: str) -> None:
        try:
            check_redirect(from_url, location, allow_plaintext=self.allow_plaintext)
        except RedirectRefused:
            if fp is not None:
                fp.close()
            raise

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("location")
        if location is None:
            location = headers.get("uri")
        if location is not None:
            self._refuse(fp, req.full_url, location)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_302
    http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._refuse(fp, req.full_url, newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_opener(
    *,
    insecure: bool = False,
    redirect: urllib.request.HTTPRedirectHandler | None = None,
) -> urllib.request.OpenerDirector:
    """Return an opener for HTTP(S) requests with a default timeout.

    urllib.request.urlopen() and build_opener() also install handlers for
    ftp://, file:// and data:, and a redirect handler that follows HTTPS to
    plain HTTP without a word. Nothing this program fetches is legitimately
    anything but HTTP(S), so this opener has the default set minus those
    three and a RedirectPolicyHandler in place of urllib's.

    With *insecure* the HTTPS handler skips certificate verification and the
    redirect policy lets HTTPS step down to plain HTTP: both are what
    --allow-insecure means. *redirect* substitutes a handler of the caller's
    own, which is how the registry transport adds credential stripping.
    """
    if redirect is None:
        redirect = RedirectPolicyHandler(allow_plaintext=insecure)
    context = insecure_ssl_context() if insecure else None
    opener = _Opener()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPDefaultErrorHandler(),
        redirect,
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


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


# The longest Retry-After this program waits out, in seconds.
#
# A 429 or 503 may say when to come back (RFC 6585 section 4, RFC 9110
# section 10.2.3), and coming back sooner only earns the same refusal.
# A longer wait is not one a command should sit through in silence -- a
# quota that refills in an hour is for the user to wait out -- so such an
# answer is reported at once.
MAX_RETRY_AFTER = 60

# Where a server reports what is left of its request quota: the IETF
# draft's header and its de facto X- predecessor. Docker Hub sends both,
# as `0;w=3600` -- nothing left in a one-hour window.
_QUOTA_REMAINING_HEADERS = ("RateLimit-Remaining", "X-RateLimit-Remaining")
_QUOTA_SPENT_RE = re.compile(r"0+[ \t]*(?:;|\Z)")
_DELTA_SECONDS_RE = re.compile(r"[0-9]+")

# The statuses whose Retry-After decides the retry. The header is the
# server's text on any answer, but these two are the ones defined to mean
# "come back then"; on a 500 it decides nothing.
_RETRY_LATER_CODES = (429, 503)


def retry_after(exc: BaseException) -> float | None:
    """Seconds the Retry-After of HTTP error *exc* asks to wait, or None.

    Both forms of the header are read: delta-seconds, and an HTTP-date
    (one already past is a wait of 0). None is a server that said nothing
    about when, which is not the same as a server that said "now". A
    number too large for a float is infinity, never an exception: the
    header is the server's text.
    """
    if not isinstance(exc, urllib.error.HTTPError) or exc.headers is None:
        return None
    value = exc.headers.get("Retry-After")
    if not isinstance(value, str):
        return None
    value = value.strip()
    if _DELTA_SECONDS_RE.fullmatch(value):
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0.0, (when - now).total_seconds())


def _quota_spent(exc: urllib.error.HTTPError) -> bool:
    """Whether HTTP error *exc* reports its request quota used up."""
    headers = getattr(exc, "headers", None)
    if headers is None:
        return False
    for name in _QUOTA_REMAINING_HEADERS:
        value = headers.get(name)
        if isinstance(value, str) and _QUOTA_SPENT_RE.match(value.strip()):
            return True
    return False


def is_retryable_http_error(exc: BaseException) -> bool:
    """Return True if a failed HTTP request is worth retrying.

    Deterministic failures are not retried, since they cannot succeed on a repeat
    request: an HTTP client error (4xx, except 408 Request Timeout and 429 Too
    Many Requests, which mean "retry later"), a TLS certificate verification
    failure, or a plaintext-HTTP reply to an https:// URL. Everything else
    (5xx server errors, connection resets, timeouts, DNS failures) is treated
    as transient and retried.

    "Later" is the server's to say. A 429 or 503 whose Retry-After asks for
    more than MAX_RETRY_AFTER is not retried, and neither is a 429 that names
    no time but reports its quota spent: a registry's pull quota refills over
    hours, so retrying it seconds apart only delays the same failure.
    """
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in _RETRY_LATER_CODES:
            wait = retry_after(exc)
            if wait is not None:
                return wait <= MAX_RETRY_AFTER
            return not (exc.code == 429 and _quota_spent(exc))
        return not (400 <= exc.code < 500 and exc.code != 408)
    if isinstance(exc, urllib.error.URLError):
        return not (is_cert_verification_error(exc) or is_plaintext_http_tls_error(exc))
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return False
    if isinstance(exc, RedirectRefused):
        # The server's answer, and it will be the same one next time.
        return False
    return isinstance(exc, (OSError, ssl.SSLError, http.client.HTTPException))


def retry_http(
    operation,
    *,
    what: str,
    max_retries: int = 5,
    retry_delay: float = 5,
    abort_event: "threading.Event | None" = None,
) -> typing.Any:
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

    The wait between attempts is *retry_delay*, or the Retry-After of a 429
    or 503 when that is longer. is_retryable_http_error has already refused
    one past MAX_RETRY_AFTER, and the wait is held to it anyway.
    """
    for attempt in range(max_retries):
        if abort_event is not None and abort_event.is_set():
            raise KeyboardInterrupt
        try:
            return operation()
        except KeyboardInterrupt:
            raise
        except NETWORK_ERRORS as exc:
            if abort_event is not None and abort_event.is_set():
                raise KeyboardInterrupt from exc
            if not is_retryable_http_error(exc) or attempt >= max_retries - 1:
                raise
            delay = retry_delay
            wait = None
            if isinstance(exc, urllib.error.HTTPError) and exc.code in _RETRY_LATER_CODES:
                wait = retry_after(exc)
            if wait is not None:
                delay = max(retry_delay, math.ceil(min(wait, MAX_RETRY_AFTER)))
            log_info(f"{what}: attempt {attempt + 1}/{max_retries} failed ({exc}); retrying in {delay}s...")
            if abort_event is not None:
                _interruptible_sleep(delay, abort_event)
            else:
                time.sleep(delay)
    return None


_READ_CHUNK = 262144  # 256 KiB
_SOCKET_TIMEOUT = 30  # seconds, so a stalled read() cannot pin a thread forever

# Outer reconnection cap for one chunk; each reconnection attempt itself
# retries up to _max_retries times internally.
_MAX_RECONNECTIONS = 10


def _ua_headers() -> dict[str, str]:
    return {"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"}


def _is_retryable(exc: BaseException) -> bool:
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
    op = http_opener(insecure=insecure)
    open_fn = functools.partial(op.open, timeout=_SOCKET_TIMEOUT)
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
    opener = http_opener(insecure=insecure)

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
                if _is_retryable(exc) and attempt < max_retries:
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
                if _is_retryable(exc) and attempt < max_retries:
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
                opener = http_opener(insecure=insecure)
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
    try:
        return _download_single_loop(
            req, dest, bucket, max_retries, retry_delays, abort_event, last_exc, insecure=insecure
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
    insecure: bool = False,
) -> None:
    url = req.full_url
    opener = http_opener(insecure=insecure)
    for attempt in range(max_retries + 1):
        if attempt > 0:
            delay = retry_delays[attempt - 1]
            warn(f"Retry {attempt}/{max_retries} in {delay}s (reason: {last_exc})...")
            _interruptible_sleep(delay, abort_event)

        try:
            with (
                atomic_replace(dest) as tmp,
                opener.open(req, timeout=_SOCKET_TIMEOUT) as resp,
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
                require_complete_body(downloaded, total, url)
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
            if _is_retryable(exc) and attempt < max_retries:
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


def _redirect_error(url: str, exc: "RedirectRefused") -> RuntimeError:
    """The error reporting a redirect refused while fetching *url*.

    Only a step down from HTTPS is what --allow-insecure lifts, so only
    that one names the flag; a redirect off HTTP is refused either way.
    """
    remedy = (
        " If you trust this source and the network path to it, re-run with "
        "'--allow-insecure' to follow the redirect."
        if exc.plaintext
        else ""
    )
    return RuntimeError(f"Cannot download {url}: {exc}{remedy}")


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
        try:
            with loading_line("Connecting..."):
                probe = _probe_server(url, _ua_headers(), insecure=insecure)
        except RedirectRefused as exc:
            raise _redirect_error(url, exc) from exc

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
                if isinstance(exc, RedirectRefused):
                    raise _redirect_error(url, exc) from exc
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

    try:
        _download_single(url, dest, bucket, insecure=insecure)
    except RedirectRefused as exc:
        raise _redirect_error(url, exc) from exc


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
