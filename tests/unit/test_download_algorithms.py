import os
import threading
import time
from unittest import mock
import urllib.error

import pytest

from chroot_distro.constants import download_max_retries, download_rate_limit
from chroot_distro.helpers.download import (
    _Segment,
    _download_segment,
    _is_retriable,
)
from chroot_distro.progress import AggregateByteProgress
from chroot_distro.rate_limit import TokenBucket


class TestTokenBucket:
    """Test TokenBucket bandwidth limiter."""

    def test_unlimited_rate(self):
        # 0 or negative rate means unlimited
        bucket = TokenBucket(0)
        start = time.monotonic()
        # Should not sleep regardless of bytes consumed
        bucket.consume(100 * 1024 * 1024)
        duration = time.monotonic() - start
        assert duration < 0.1

    def test_rate_limiting_sleep(self):
        # Rate of 1000 bytes/sec
        bucket = TokenBucket(1000)
        # Force initial tokens to be 0
        bucket._tokens = 0.0
        bucket._last = time.monotonic()

        start = time.monotonic()
        # Consume 1000 bytes -> should take ~1 second to refill and allow
        bucket.consume(1000)
        duration = time.monotonic() - start
        assert duration >= 0.8  # should be around 1.0 second

    def test_suffix_parsing(self, monkeypatch):
        # No env -> 0 (unlimited)
        monkeypatch.delenv("CD_DOWNLOAD_RATE_LIMIT", raising=False)
        assert download_rate_limit() == 0

        # Empty/whitespace -> 0
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "   ")
        assert download_rate_limit() == 0

        # Simple integer
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "500")
        assert download_rate_limit() == 500

        # K suffix (KiB)
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "20K")
        assert download_rate_limit() == 20 * 1024

        # M suffix (MiB)
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "5M")
        assert download_rate_limit() == 5 * 1024 * 1024

        # G suffix (GiB)
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "1G")
        assert download_rate_limit() == 1024 * 1024 * 1024

        # Case insensitive
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "150k")
        assert download_rate_limit() == 150 * 1024

        # Invalid format -> fallback to 0
        monkeypatch.setenv("CD_DOWNLOAD_RATE_LIMIT", "invalid")
        assert download_rate_limit() == 0


class TestConfigurableRetries:
    """Test CD_DOWNLOAD_MAX_RETRIES env parsing."""

    def test_retry_parsing(self, monkeypatch):
        # Default fallback
        monkeypatch.delenv("CD_DOWNLOAD_MAX_RETRIES", raising=False)
        assert download_max_retries() == 3

        # Custom value
        monkeypatch.setenv("CD_DOWNLOAD_MAX_RETRIES", "5")
        assert download_max_retries() == 5

        # Invalid -> fallback
        monkeypatch.setenv("CD_DOWNLOAD_MAX_RETRIES", "abc")
        assert download_max_retries() == 3

        # Underflow
        monkeypatch.setenv("CD_DOWNLOAD_MAX_RETRIES", "-1")
        assert download_max_retries() == 0

        # Overflow
        monkeypatch.setenv("CD_DOWNLOAD_MAX_RETRIES", "999")
        assert download_max_retries() == 20


class TestSpeedTracking:
    """Test AggregateByteProgress sliding-window speed tracking."""

    def test_speed_calculation(self):
        # Create progress tracker
        progress = AggregateByteProgress(1000, label="speed_test")

        # Fake the sample history: 100 bytes at time T, 600 bytes at time T+2
        now = time.monotonic()
        progress._samples.clear()
        progress._samples.append((now - 2.0, 100))
        progress._samples.append((now, 600))

        # Speed = (600 - 100) / 2.0 = 250 bytes/sec
        assert pytest.approx(progress.speed(), 0.1) == 250.0


class TestSegmentReconnection:
    """Test per-chunk segment level reconnection and recovery."""

    def test_is_retriable(self):
        # Transient errors should be retriable
        assert _is_retriable(ConnectionResetError())
        assert _is_retriable(TimeoutError())
        assert _is_retriable(urllib.error.HTTPError("http://ex.com", 503, "Service Unavailable", {}, None))

        # Non-transient errors
        assert not _is_retriable(ValueError())
        assert not _is_retriable(urllib.error.HTTPError("http://ex.com", 404, "Not Found", {}, None))

    def test_reconnection_success_after_failure(self, tmp_path):
        seg_path = str(tmp_path / "chunk0.tmp")
        seg = _Segment(index=0, start=0, end=9, tmp_path=seg_path)

        calls = 0

        class FakeOpener:
            def open(self, req, timeout=None):
                nonlocal calls
                calls += 1
                range_header = req.headers.get("Range", "")

                if calls == 1:
                    # First connection reads 5 bytes, then drops
                    assert range_header == "bytes=0-9"
                    class BrokenStream:
                        def __init__(self):
                            self.called = False
                        def read(self, size):
                            if not self.called:
                                self.called = True
                                return b"ABCDE"
                            raise ConnectionResetError("Connection reset by peer")
                    stream = BrokenStream()
                    m = mock.MagicMock(status=206, read=stream.read)
                    m.__enter__.return_value = m
                    return m
                else:
                    # Second connection resumes from byte offset 5
                    assert range_header == "bytes=5-9"
                    class RestStream:
                        def __init__(self):
                            self.called = False
                        def read(self, size):
                            if not self.called:
                                self.called = True
                                return b"FGHIJ"
                            return b""
                    stream = RestStream()
                    m = mock.MagicMock(status=206, read=stream.read)
                    m.__enter__.return_value = m
                    return m

        mock_opener = FakeOpener()
        abort_event = threading.Event()

        # Mock the build_opener and sleep
        with (
            mock.patch("urllib.request.build_opener", return_value=mock_opener),
            mock.patch("chroot_distro.helpers.download._interruptible_sleep"),
            mock.patch("chroot_distro.helpers.download._get_max_retries", return_value=1),
        ):
            _download_segment(
                seg=seg,
                url="http://cdn.example.com/file",
                ua_headers={},
                aggregate=None,
                abort_event=abort_event,
                bucket=None,
            )

        # File should be completely downloaded with correct content
        assert os.path.getsize(seg_path) == 10
        with open(seg_path, "rb") as f:
            assert f.read() == b"ABCDEFGHIJ"
