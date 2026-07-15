"""Tests for download cancellation: _LiveResponses socket shutdown,
abort-aware retry_http, and _download_segment abort checks."""

from __future__ import annotations

import socket
import threading
import time
import urllib.error
from unittest import mock

import pytest

from chroot_distro.helpers.download import (
    _download_segment,
    _LiveResponses,
    _response_socket,
    _Segment,
    retry_http,
)

# ---------------------------------------------------------------------------
# _LiveResponses.close_all() must not deadlock behind a blocked read()
# ---------------------------------------------------------------------------


class _SocketBackedResp:
    """Mimics http.client.HTTPResponse's fp -> BufferedReader -> SocketIO
    -> _sock layout over a real socketpair."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self.fp = sock.makefile("rb")  # BufferedReader whose .raw._sock is sock

    def read(self, n: int = -1) -> bytes:
        return self.fp.read(n)

    def close(self) -> None:
        self.fp.close()


class TestLiveResponsesShutdown:
    def test_response_socket_extraction(self):
        srv, cli = socket.socketpair()
        try:
            resp = _SocketBackedResp(cli)
            assert _response_socket(resp) is cli
        finally:
            srv.close()
            cli.close()

    def test_response_socket_none_when_closed(self):
        srv, cli = socket.socketpair()
        resp = _SocketBackedResp(cli)
        resp.close()
        srv.close()
        cli.close()
        # Must not raise on a closed BufferedReader; a closed socket is
        # acceptable too — shutdown() on it is a harmless suppressed error.
        sock = _response_socket(resp)
        assert sock is None or sock.fileno() == -1

    def test_close_all_unblocks_blocked_reader(self):
        """close_all() from one thread must return promptly and unblock a
        reader thread stuck in resp.read() — the ^C^C^C deadlock repro."""
        srv, cli = socket.socketpair()
        resp = _SocketBackedResp(cli)
        live = _LiveResponses(lock=threading.Lock(), responses=set())
        live.add(resp)

        reader_done = threading.Event()

        def _reader():
            # Blocks in recv: server never sends the requested bytes.
            resp.read(100)
            reader_done.set()

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        time.sleep(0.2)  # let the reader block inside read()

        start = time.monotonic()
        live.close_all()  # old code deadlocked here behind the buffer lock
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"close_all() blocked for {elapsed:.1f}s"
        assert reader_done.wait(2.0), "reader thread never unblocked"
        srv.close()
        cli.close()

    def test_close_all_without_socket_falls_back_to_close(self):
        resp = mock.MagicMock()
        resp.fp = None  # already-closed response: no socket to shut down
        live = _LiveResponses(lock=threading.Lock(), responses={resp})
        live.close_all()
        resp.close.assert_called_once()
        assert not live.responses


# ---------------------------------------------------------------------------
# retry_http abort awareness
# ---------------------------------------------------------------------------


class TestRetryHttpAbort:
    def test_abort_before_first_attempt(self):
        abort = threading.Event()
        abort.set()
        op = mock.MagicMock()
        with pytest.raises(KeyboardInterrupt):
            retry_http(op, what="test", abort_event=abort)
        op.assert_not_called()

    def test_abort_set_during_operation_converts_oserror(self):
        """A force-closed socket surfaces as OSError; when the abort flag is
        set that must become KeyboardInterrupt, not a 5s sleep + retry."""
        abort = threading.Event()

        def _op():
            abort.set()  # simulates SIGINT closing the socket mid-request
            raise OSError("Connection reset by force-close")

        start = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            retry_http(_op, what="test", max_retries=5, retry_delay=5, abort_event=abort)
        assert time.monotonic() - start < 1.0, "retry_http slept instead of aborting"

    def test_retry_sleep_is_interruptible(self):
        """An abort raised while waiting between retries must cut the sleep."""
        abort = threading.Event()
        calls = {"n": 0}

        def _op():
            calls["n"] += 1
            raise TimeoutError("transient")

        def _abort_soon():
            time.sleep(0.3)
            abort.set()

        threading.Thread(target=_abort_soon, daemon=True).start()
        start = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            retry_http(_op, what="test", max_retries=3, retry_delay=30, abort_event=abort)
        assert time.monotonic() - start < 5.0, "retry delay was not interruptible"
        assert calls["n"] == 1

    def test_no_abort_event_keeps_old_behaviour(self):
        op = mock.MagicMock(side_effect=[TimeoutError("t"), b"ok"])
        result = retry_http(op, what="test", max_retries=3, retry_delay=0)
        assert result == b"ok"
        assert op.call_count == 2

    def test_deterministic_error_still_raised_immediately(self):
        err = urllib.error.HTTPError("http://x", 404, "Not Found", None, None)  # type: ignore[arg-type]
        op = mock.MagicMock(side_effect=err)
        with pytest.raises(urllib.error.HTTPError):
            retry_http(op, what="test", abort_event=threading.Event())
        op.assert_called_once()


# ---------------------------------------------------------------------------
# _download_segment abort checks
# ---------------------------------------------------------------------------


class TestDownloadSegmentAbort:
    def test_no_connection_opened_after_abort(self, tmp_path):
        """A pre-set abort must raise before opener.open() is ever called."""
        seg = _Segment(index=0, start=0, end=99, tmp_path=str(tmp_path / "chunk0.tmp"))
        abort = threading.Event()
        abort.set()
        opener = mock.MagicMock()
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            pytest.raises(KeyboardInterrupt),
        ):
            _download_segment(seg, "http://example.com/f", {}, None, abort)
        opener.open.assert_not_called()

    def test_oserror_with_abort_set_becomes_keyboard_interrupt(self, tmp_path):
        """When the SIGINT handler force-closes the socket, the resulting
        OSError must not trigger the retry/reconnect ladder."""
        seg = _Segment(index=0, start=0, end=99, tmp_path=str(tmp_path / "chunk0.tmp"))
        abort = threading.Event()

        def _open(*_a, **_k):
            abort.set()  # abort lands while the request is in flight
            raise OSError("Socket closed by abort")

        opener = mock.MagicMock()
        opener.open.side_effect = _open
        start = time.monotonic()
        with (
            mock.patch("urllib.request.build_opener", return_value=opener),
            pytest.raises(KeyboardInterrupt),
        ):
            _download_segment(seg, "http://example.com/f", {}, None, abort)
        assert time.monotonic() - start < 1.0, "segment retried/reconnected past the abort"
        assert opener.open.call_count == 1
