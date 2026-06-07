"""Tests for multi-connection segmented download in helpers/download.py."""

from __future__ import annotations

import io
import os
import ssl
import threading
import urllib.error
from unittest import mock

import pytest

from chroot_distro.helpers.download import (
    _compute_segments,
    _concat_chunks,
    _download_segment,
    _is_retriable,
    _probe_server,
    _ProbeResult,
    _RangeNotSupportedError,
    _Segment,
    download_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResp:
    """Minimal fake urllib response for testing."""

    def __init__(
        self,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        url: str = "http://example.com/file.tar",
    ):
        self.status = status
        self._headers = headers or {}
        self._body = io.BytesIO(body)
        self.url = url
        self.headers = _FakeHeaders(self._headers)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _FakeHeaders:
    def __init__(self, d: dict[str, str]):
        self._d = d

    def get(self, key: str, default: str = "") -> str:
        return self._d.get(key, default)


# ---------------------------------------------------------------------------
# _probe_server tests
# ---------------------------------------------------------------------------


class TestProbeServer:
    """Tests for _probe_server()."""

    def test_range_ok(self):
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1024", "Accept-Ranges": "bytes"},
            url="http://cdn.example.com/final.tar",
        )
        with mock.patch("urllib.request.urlopen", return_value=resp):
            result = _probe_server("http://example.com/file.tar", {})
        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 1024
        assert result.final_url == "http://cdn.example.com/final.tar"

    def test_no_range_header(self):
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "2048"},
        )
        with mock.patch("urllib.request.urlopen", return_value=resp):
            result = _probe_server("http://example.com/file.tar", {})
        assert result is not None
        assert result.range_ok is False
        assert result.content_length == 2048

    def test_range_none(self):
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "512", "Accept-Ranges": "none"},
        )
        with mock.patch("urllib.request.urlopen", return_value=resp):
            result = _probe_server("http://example.com/file.tar", {})
        assert result is not None
        assert result.range_ok is False

    def test_head_405_fallback_to_get(self):
        """HEAD returns 405 → fallback GET Range:0-0 → 206."""
        import urllib.error

        head_exc = urllib.error.HTTPError("http://example.com/file.tar", 405, "Method Not Allowed", {}, None)
        get_resp = _FakeResp(
            status=206,
            headers={"Content-Range": "bytes 0-0/4096"},
            body=b"\x00",
            url="http://cdn.example.com/final.tar",
        )

        call_count = 0

        def _urlopen_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise head_exc
            return get_resp

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            result = _probe_server("http://example.com/file.tar", {})
        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 4096

    def test_network_error(self):
        import urllib.error

        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            result = _probe_server("http://example.com/file.tar", {})
        assert result is None


# ---------------------------------------------------------------------------
# _compute_segments tests
# ---------------------------------------------------------------------------


class TestComputeSegments:
    """Tests for _compute_segments()."""

    def test_even_split(self):
        total = 32 * 1024 * 1024  # 32 MiB — well above MIN_SEGMENT_BYTES
        segs = _compute_segments(total, 4, "/tmp/test")
        assert len(segs) == 4
        # No gaps, no overlap
        for i in range(len(segs) - 1):
            assert segs[i].end + 1 == segs[i + 1].start
        assert segs[0].start == 0
        assert segs[-1].end == total - 1

    def test_remainder_absorbed_by_last(self):
        total = 32 * 1024 * 1024 + 1  # not evenly divisible
        segs = _compute_segments(total, 4, "/tmp/test")
        assert len(segs) == 4
        assert segs[-1].end == total - 1
        total_bytes = sum(s.end - s.start + 1 for s in segs)
        assert total_bytes == total

    def test_min_segment_enforcement(self):
        """6 MiB file with n=4 and MIN=4MiB → reduces to 1 segment."""
        total = 6 * 1024 * 1024  # 6 MiB
        segs = _compute_segments(total, 4, "/tmp/test")
        assert len(segs) == 1
        assert segs[0].start == 0
        assert segs[0].end == total - 1

    def test_large_file_keeps_requested_segments(self):
        """32 MiB file with n=4 → all 4 segments."""
        total = 32 * 1024 * 1024
        segs = _compute_segments(total, 4, "/tmp/test")
        assert len(segs) == 4

    def test_tmp_path_format(self):
        segs = _compute_segments(100 * 1024 * 1024, 3, "/cache/file.tar")
        for i, seg in enumerate(segs):
            assert seg.tmp_path == f"/cache/file.tar.chunk{i}.tmp"


# ---------------------------------------------------------------------------
# _download_segment tests
# ---------------------------------------------------------------------------


class TestDownloadSegment:
    """Tests for _download_segment()."""

    @staticmethod
    def _mock_opener(resp):
        """Return a mock opener whose .open() yields *resp*."""
        opener = mock.MagicMock()
        opener.open.return_value = resp
        return opener

    def test_returns_200_raises_range_not_supported(self, tmp_path):
        seg = _Segment(index=0, start=0, end=99, tmp_path=str(tmp_path / "chunk0.tmp"))
        resp = _FakeResp(status=200, body=b"x" * 100)
        abort = threading.Event()
        with (
            mock.patch("urllib.request.build_opener", return_value=self._mock_opener(resp)),
            pytest.raises(_RangeNotSupportedError),
        ):
            _download_segment(seg, "http://example.com/f", {}, None, abort)

    def test_size_mismatch_raises(self, tmp_path):
        seg = _Segment(index=0, start=0, end=99, tmp_path=str(tmp_path / "chunk0.tmp"))
        # Only send 50 bytes but segment expects 100
        resp = _FakeResp(status=206, body=b"x" * 50)
        abort = threading.Event()
        with (
            mock.patch("urllib.request.build_opener", return_value=self._mock_opener(resp)),
            pytest.raises(RuntimeError, match="expected 100 bytes, got 50"),
        ):
            _download_segment(seg, "http://example.com/f", {}, None, abort)

    def test_successful_download(self, tmp_path):
        seg = _Segment(index=0, start=0, end=99, tmp_path=str(tmp_path / "chunk0.tmp"))
        body = b"A" * 100
        resp = _FakeResp(status=206, body=body)
        abort = threading.Event()
        with mock.patch("urllib.request.build_opener", return_value=self._mock_opener(resp)):
            _download_segment(seg, "http://example.com/f", {}, None, abort)
        assert os.path.getsize(seg.tmp_path) == 100
        with open(seg.tmp_path, "rb") as f:
            assert f.read() == body

    def test_abort_event_raises_keyboard_interrupt(self, tmp_path):
        seg = _Segment(index=0, start=0, end=9999, tmp_path=str(tmp_path / "chunk0.tmp"))

        # Create response that yields data slowly
        class SlowResp(_FakeResp):
            def read(self, n=-1):
                return b"x" * min(n, 1024) if n > 0 else b""

        resp = SlowResp(status=206, body=b"")
        abort = threading.Event()
        abort.set()  # pre-set abort

        with (
            mock.patch("urllib.request.build_opener", return_value=self._mock_opener(resp)),
            pytest.raises(KeyboardInterrupt),
        ):
            _download_segment(seg, "http://example.com/f", {}, None, abort)


# ---------------------------------------------------------------------------
# _concat_chunks tests
# ---------------------------------------------------------------------------


class TestConcatChunks:
    """Tests for _concat_chunks()."""

    def test_concatenation_order(self, tmp_path):
        dest = str(tmp_path / "output.tar")
        segments = []
        for i, content in enumerate([b"AAA", b"BBB", b"CCC"]):
            seg_path = str(tmp_path / f"chunk{i}.tmp")
            with open(seg_path, "wb") as f:
                f.write(content)
            segments.append(_Segment(index=i, start=0, end=0, tmp_path=seg_path))

        _concat_chunks(segments, dest)
        with open(dest, "rb") as f:
            assert f.read() == b"AAABBBCCC"

    def test_out_of_order_segments_sorted(self, tmp_path):
        """Segments passed out of order still concatenated by index."""
        dest = str(tmp_path / "output.tar")
        segments = []
        for i, content in [(2, b"CC"), (0, b"AA"), (1, b"BB")]:
            seg_path = str(tmp_path / f"chunk{i}.tmp")
            with open(seg_path, "wb") as f:
                f.write(content)
            segments.append(_Segment(index=i, start=0, end=0, tmp_path=seg_path))

        _concat_chunks(segments, dest)
        with open(dest, "rb") as f:
            assert f.read() == b"AABBCC"


# ---------------------------------------------------------------------------
# download_file integration tests
# ---------------------------------------------------------------------------


class TestDownloadFile:
    """Integration tests for download_file() dispatcher."""

    def test_single_connection_when_workers_1(self, tmp_path):
        dest = str(tmp_path / "file.tar")
        body = b"hello world"
        resp = _FakeResp(status=200, headers={"Content-Length": str(len(body))}, body=body)

        with (
            mock.patch("chroot_distro.constants.layer_download_workers", return_value=1),
            mock.patch("urllib.request.urlopen", return_value=resp),
            mock.patch("chroot_distro.helpers.download.atomic_replace") as mock_ar,
        ):
            mock_ar.return_value.__enter__ = mock.Mock(return_value=dest)
            mock_ar.return_value.__exit__ = mock.Mock(return_value=False)
            download_file("http://example.com/file.tar", dest)

        with open(dest, "rb") as f:
            assert f.read() == body

    def test_fallback_when_no_range_support(self, tmp_path):
        dest = str(tmp_path / "file.tar")
        body = b"data" * 100

        # _probe_server returns range_ok=False → falls back to _download_single
        fake_probe = _ProbeResult(content_length=len(body), final_url="http://example.com/file.tar", range_ok=False)
        single_resp = _FakeResp(
            status=200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

        with (
            mock.patch("chroot_distro.constants.layer_download_workers", return_value=4),
            mock.patch("chroot_distro.helpers.download._probe_server", return_value=fake_probe),
            mock.patch("urllib.request.urlopen", return_value=single_resp),
            mock.patch("chroot_distro.helpers.download.atomic_replace") as mock_ar,
        ):
            mock_ar.return_value.__enter__ = mock.Mock(return_value=dest)
            mock_ar.return_value.__exit__ = mock.Mock(return_value=False)
            download_file("http://example.com/file.tar", dest)

        with open(dest, "rb") as f:
            assert f.read() == body

    def test_download_file_resume(self, tmp_path):
        dest = str(tmp_path / "output.tar")
        content = b"X" * (8 * 1024 * 1024)

        probe_result = _ProbeResult(
            content_length=len(content),
            final_url="http://cdn.example.com/final.tar",
            range_ok=True,
        )

        # Mock build_opener for 1st run: segment 0 succeeds, segment 1 fails
        def mock_open_first(req, *args, **kwargs):
            range_header = req.headers.get("Range", "")
            if range_header == "bytes=0-4194303":
                return _FakeResp(status=206, body=b"X" * (4 * 1024 * 1024))
            elif range_header == "bytes=4194304-8388607":

                class BrokenStream:
                    def __init__(self):
                        self.bytes_read = 0

                    def read(self, n):
                        if self.bytes_read >= 1024 * 1024:
                            chunk0_path = f"{dest}.chunk0.tmp"
                            import time
                            for _ in range(50):
                                if os.path.isfile(chunk0_path) and os.path.getsize(chunk0_path) == 4 * 1024 * 1024:
                                    break
                                time.sleep(0.1)
                            raise ConnectionResetError("Connection reset by peer")
                        chunk = b"X" * min(n, 1024 * 1024 - self.bytes_read)
                        self.bytes_read += len(chunk)
                        return chunk

                resp = _FakeResp(status=206)
                resp._body = BrokenStream()
                return resp
            else:
                raise ConnectionResetError("Connection reset by peer")

        mock_opener_first = mock.MagicMock()
        mock_opener_first.open.side_effect = mock_open_first

        with (
            mock.patch("chroot_distro.constants.layer_download_workers", return_value=4),
            mock.patch("chroot_distro.helpers.download._probe_server", return_value=probe_result),
            mock.patch("urllib.request.build_opener", return_value=mock_opener_first),
            mock.patch("chroot_distro.helpers.download._interruptible_sleep"),
        ):
            with pytest.raises(Exception):
                download_file("http://example.com/output.tar", dest)

        chunks_json = f"{dest}.chunks.json"
        assert os.path.isfile(chunks_json)
        assert os.path.isfile(f"{dest}.chunk0.tmp")
        assert os.path.isfile(f"{dest}.chunk1.tmp")
        assert os.path.getsize(f"{dest}.chunk0.tmp") == 4 * 1024 * 1024
        assert os.path.getsize(f"{dest}.chunk1.tmp") == 1024 * 1024

        # 2nd run: resume and complete
        captured_ranges = []

        def mock_open_second(req, *args, **kwargs):
            range_header = req.headers.get("Range", "")
            captured_ranges.append(range_header)
            if range_header == "bytes=5242880-8388607":
                return _FakeResp(status=206, body=b"X" * (3 * 1024 * 1024))
            else:
                return _FakeResp(status=200)

        mock_opener_second = mock.MagicMock()
        mock_opener_second.open.side_effect = mock_open_second

        with (
            mock.patch("chroot_distro.constants.layer_download_workers", return_value=4),
            mock.patch("chroot_distro.helpers.download._probe_server", return_value=probe_result),
            mock.patch("urllib.request.build_opener", return_value=mock_opener_second),
            mock.patch("chroot_distro.helpers.download._interruptible_sleep"),
        ):
            download_file("http://example.com/output.tar", dest)

        assert os.path.isfile(dest)
        with open(dest, "rb") as f:
            assert f.read() == content

        # Only segment 1 should have been downloaded since segment 0 was complete.
        assert len(captured_ranges) == 1
        assert captured_ranges[0] == "bytes=5242880-8388607"

        # Check clean up on success
        assert not os.path.isfile(chunks_json)
        assert not os.path.isfile(f"{dest}.chunk0.tmp")
        assert not os.path.isfile(f"{dest}.chunk1.tmp")


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for download-related constants."""

    def test_min_segment_bytes_value(self):
        from chroot_distro.constants import MIN_SEGMENT_BYTES

        assert MIN_SEGMENT_BYTES == 4 * 1024 * 1024

    def test_layer_download_workers_env(self, monkeypatch):
        from chroot_distro.constants import layer_download_workers

        monkeypatch.setenv("CD_DOWNLOAD_WORKERS", "3")
        assert layer_download_workers() == 3

    def test_layer_download_workers_clamp(self, monkeypatch):
        from chroot_distro.constants import MAX_LAYER_DOWNLOAD_WORKERS, layer_download_workers

        monkeypatch.setenv("CD_DOWNLOAD_WORKERS", "99")
        assert layer_download_workers() == MAX_LAYER_DOWNLOAD_WORKERS

    def test_layer_download_workers_invalid(self, monkeypatch):
        from chroot_distro.constants import DEFAULT_LAYER_DOWNLOAD_WORKERS, layer_download_workers

        monkeypatch.setenv("CD_DOWNLOAD_WORKERS", "abc")
        assert layer_download_workers() == DEFAULT_LAYER_DOWNLOAD_WORKERS


# ---------------------------------------------------------------------------
# Two-stage Range detection tests
# ---------------------------------------------------------------------------


class TestTwoStageRangeDetection:
    """Tests for the two-stage HEAD → GET probe strategy."""

    def test_head_no_accept_ranges_but_range_works(self):
        """HEAD omits Accept-Ranges header; GET bytes=0-0 → 206.

        This is the primary scenario that was broken before: many CDNs
        support Range requests but don't include Accept-Ranges in HEAD.
        """
        head_resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1048576"},  # no Accept-Ranges!
            url="http://cdn.example.com/final.tar",
        )
        get_resp = _FakeResp(
            status=206,
            headers={"Content-Range": "bytes 0-0/1048576"},
            body=b"\x00",
            url="http://cdn.example.com/final.tar",
        )

        call_count = 0

        def _urlopen_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # HEAD request
                return head_resp
            # GET Range:0-0 request
            return get_resp

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            result = _probe_server("http://example.com/file.tar", {})

        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 1048576
        assert call_count == 2  # HEAD + GET

    def test_head_no_accept_ranges_and_range_fails(self):
        """HEAD omits Accept-Ranges; GET bytes=0-0 → 200 (no range support)."""
        head_resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1048576"},
            url="http://example.com/file.tar",
        )
        get_resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1048576"},
            body=b"\x00",
            url="http://example.com/file.tar",
        )

        call_count = 0

        def _urlopen_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return head_resp
            return get_resp

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            result = _probe_server("http://example.com/file.tar", {})

        assert result is not None
        assert result.range_ok is False
        assert call_count == 2

    def test_head_accept_ranges_none_skips_get_probe(self):
        """Accept-Ranges: none → don't bother with GET probe."""
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1024", "Accept-Ranges": "none"},
            url="http://example.com/file.tar",
        )

        call_count = 0

        def _urlopen_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            return resp

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            result = _probe_server("http://example.com/file.tar", {})

        assert result is not None
        assert result.range_ok is False
        assert call_count == 1  # Only HEAD, no GET probe

    def test_head_zero_content_length_skips_get_probe(self):
        """HEAD returns no Content-Length → no point probing ranges."""
        resp = _FakeResp(
            status=200,
            headers={},  # no Content-Length, no Accept-Ranges
            url="http://example.com/file.tar",
        )

        call_count = 0

        def _urlopen_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            return resp

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen_side_effect):
            result = _probe_server("http://example.com/file.tar", {})

        assert result is not None
        assert result.range_ok is False
        assert call_count == 1  # Only HEAD, no GET probe


# ---------------------------------------------------------------------------
# _is_retriable tests
# ---------------------------------------------------------------------------


class TestIsRetriable:
    """Tests for _is_retriable() expanded coverage."""

    def test_timeout_error(self):
        assert _is_retriable(TimeoutError("connection timed out")) is True

    def test_ssl_error(self):
        assert _is_retriable(ssl.SSLError("SSL handshake failed")) is True

    def test_connection_reset(self):
        assert _is_retriable(ConnectionResetError("reset by peer")) is True

    def test_broken_pipe(self):
        assert _is_retriable(BrokenPipeError("broken pipe")) is True

    def test_os_error(self):
        assert _is_retriable(OSError("network unreachable")) is True

    def test_http_500(self):
        exc = urllib.error.HTTPError("http://x", 500, "Server Error", {}, None)
        assert _is_retriable(exc) is True

    def test_http_404_not_retriable(self):
        exc = urllib.error.HTTPError("http://x", 404, "Not Found", {}, None)
        assert _is_retriable(exc) is False

    def test_value_error_not_retriable(self):
        assert _is_retriable(ValueError("bad value")) is False

    def test_url_error_with_timeout_reason(self):
        exc = urllib.error.URLError(TimeoutError("timed out"))
        assert _is_retriable(exc) is True
