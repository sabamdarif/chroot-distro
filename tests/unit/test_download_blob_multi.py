"""Tests for multi-connection segmented blob download in helpers/docker/layers.py."""

from __future__ import annotations

import io
import os
import threading
import urllib.error
import urllib.parse
from unittest import mock

import pytest

from chroot_distro.helpers.docker.layers import (
    _probe_blob,
    download_blob,
)
from chroot_distro.helpers.download import (
    _FallbackToSingleError,
    _ProbeResult,
    _Segment,
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
        url: str = "https://registry-1.docker.io/v2/library/nextcloud/blobs/sha256:1234567890abcdef",
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
# _probe_blob tests
# ---------------------------------------------------------------------------


class TestProbeBlob:
    """Tests for _probe_blob()."""

    def test_range_ok(self):
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1024", "Accept-Ranges": "bytes"},
            url="https://cdn.example.com/final.blob",
        )
        mock_opener = mock.MagicMock()
        mock_opener.open.return_value = resp
        with mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener):
            result = _probe_blob("https://registry-1.docker.io/v2/f", {})
        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 1024
        assert result.final_url == "https://cdn.example.com/final.blob"

    def test_no_range_header(self):
        resp = _FakeResp(
            status=200,
            headers={"Content-Length": "2048"},
        )
        mock_opener = mock.MagicMock()
        mock_opener.open.return_value = resp
        with mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener):
            result = _probe_blob("https://registry-1.docker.io/v2/f", {})
        assert result is not None
        assert result.range_ok is False
        assert result.content_length == 2048

    def test_head_405_fallback_to_get(self):
        """HEAD returns 405 -> fallback GET Range:0-0 -> 206."""
        head_exc = urllib.error.HTTPError("https://registry-1.docker.io/v2/f", 405, "Method Not Allowed", {}, None)
        get_resp = _FakeResp(
            status=206,
            headers={"Content-Range": "bytes 0-0/4096"},
            body=b"\x00",
            url="https://cdn.example.com/final.blob",
        )

        mock_opener = mock.MagicMock()
        call_count = 0

        def _open_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise head_exc
            return get_resp

        mock_opener.open.side_effect = _open_side_effect
        with mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener):
            result = _probe_blob("https://registry-1.docker.io/v2/f", {})
        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 4096

    def test_network_error(self):
        mock_opener = mock.MagicMock()
        mock_opener.open.side_effect = urllib.error.URLError("Connection refused")
        with mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener):
            result = _probe_blob("https://registry-1.docker.io/v2/f", {})
        assert result is None

    def test_no_accept_ranges_but_range_works(self):
        """HEAD omits Accept-Ranges; GET bytes=0-0 → 206.

        Verifies the two-stage probe works through the blob auth_opener path.
        """
        head_resp = _FakeResp(
            status=200,
            headers={"Content-Length": "1048576"},  # no Accept-Ranges!
            url="https://cdn.example.com/final.blob",
        )
        get_resp = _FakeResp(
            status=206,
            headers={"Content-Range": "bytes 0-0/1048576"},
            body=b"\x00",
            url="https://cdn.example.com/final.blob",
        )

        mock_opener = mock.MagicMock()
        call_count = 0

        def _open_side_effect(req, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return head_resp
            return get_resp

        mock_opener.open.side_effect = _open_side_effect
        with mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener):
            result = _probe_blob("https://registry-1.docker.io/v2/f", {})

        assert result is not None
        assert result.range_ok is True
        assert result.content_length == 1048576
        assert call_count == 2  # HEAD + GET


# ---------------------------------------------------------------------------
# download_blob segmented tests
# ---------------------------------------------------------------------------


class TestDownloadBlobSegmented:
    """Tests for download_blob() when connections > 1."""

    @pytest.fixture
    def mock_cache_path(self, tmp_path):
        digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        path = str(tmp_path / "cache_file")
        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            yield digest, path

    def test_successful_segmented_download(self, mock_cache_path, tmp_path):
        digest, path = mock_cache_path
        content = b"A" * (8 * 1024 * 1024)  # 8 MiB (forces 2 segments of 4MiB)
        import hashlib

        expected_hex = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{expected_hex}"
        path = str(tmp_path / f"layer_{expected_hex}")

        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            probe_result = _ProbeResult(
                content_length=len(content),
                final_url="https://cdn.example.com/final.blob",
                range_ok=True,
            )

            # Mock _download_segment to write part of the content to seg.tmp_path
            def mock_download_segment(seg, url, headers, progress, abort):
                with open(seg.tmp_path, "wb") as f:
                    f.write(content[seg.start : seg.end + 1])

            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_result),
                mock.patch("chroot_distro.helpers.docker.layers._download_segment", side_effect=mock_download_segment),
            ):
                result_path = download_blob(
                    repo="library/nextcloud",
                    digest=digest,
                    token="test_token",
                    connections=2,
                )

        assert result_path == path
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            assert f.read() == content

    def test_integrity_check_failed(self, mock_cache_path, tmp_path):
        digest, path = mock_cache_path
        content = b"A" * (8 * 1024 * 1024)
        # Expected hash is correct for b"A" * 8MiB, but we will write different data to cause validation error
        import hashlib

        expected_hex = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{expected_hex}"
        path = str(tmp_path / f"layer_{expected_hex}")

        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            probe_result = _ProbeResult(
                content_length=len(content),
                final_url="https://cdn.example.com/final.blob",
                range_ok=True,
            )

            # Write bad data
            def mock_download_segment_bad(seg, url, headers, progress, abort):
                with open(seg.tmp_path, "wb") as f:
                    f.write(b"B" * (seg.end - seg.start + 1))

            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_result),
                mock.patch(
                    "chroot_distro.helpers.docker.layers._download_segment", side_effect=mock_download_segment_bad
                ),
            ):
                with pytest.raises(RuntimeError, match="Layer integrity check failed"):
                    download_blob(
                        repo="library/nextcloud",
                        digest=digest,
                        token="test_token",
                        connections=2,
                    )
        # Ensure target file was not created due to atomic replace failure
        assert not os.path.isfile(path)

    def test_auth_headers_presence(self, mock_cache_path, tmp_path):
        digest, path = mock_cache_path
        content = b"A" * (8 * 1024 * 1024)
        import hashlib

        expected_hex = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{expected_hex}"
        path = str(tmp_path / f"layer_{expected_hex}")

        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            # Case 1: Cross-host redirect (final_url has different host). Authorization should NOT be present.
            probe_cross_host = _ProbeResult(
                content_length=len(content),
                final_url="https://cdn.example.com/final.blob",
                range_ok=True,
            )

            captured_headers = []

            def mock_dl_segment(seg, url, headers, progress, abort):
                captured_headers.append(headers)
                with open(seg.tmp_path, "wb") as f:
                    f.write(content[seg.start : seg.end + 1])

            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_cross_host),
                mock.patch("chroot_distro.helpers.docker.layers._download_segment", side_effect=mock_dl_segment),
            ):
                download_blob(
                    repo="library/nextcloud",
                    digest=digest,
                    token="my_secret_token",
                    connections=2,
                )

            for h in captured_headers:
                assert "Authorization" not in h

            # Case 2: Same host registry (final_url is on same host). Authorization MUST be present.
            probe_same_host = _ProbeResult(
                content_length=len(content),
                final_url="https://registry-1.docker.io/v2/library/nextcloud/blobs/sha256/abc",
                range_ok=True,
            )

            captured_headers.clear()
            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_same_host),
                mock.patch("chroot_distro.helpers.docker.layers._download_segment", side_effect=mock_dl_segment),
            ):
                download_blob(
                    repo="library/nextcloud",
                    digest=digest,
                    token="my_secret_token",
                    connections=2,
                )

            for h in captured_headers:
                assert h.get("Authorization") == "Bearer my_secret_token"

    def test_fallback_on_segment_download_error(self, mock_cache_path, tmp_path):
        digest, path = mock_cache_path
        content = b"A" * 100
        import hashlib

        expected_hex = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{expected_hex}"
        path = str(tmp_path / f"layer_{expected_hex}")

        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            probe_result = _ProbeResult(
                content_length=len(content),
                final_url="https://cdn.example.com/final.blob",
                range_ok=True,
            )

            # Mock _download_segment to fail
            def mock_dl_segment_error(seg, url, headers, progress, abort):
                raise RuntimeError("segment download failed")

            # Mock single connection download as success
            single_resp = _FakeResp(status=200, body=content, url="https://cdn.example.com/final.blob")
            mock_opener = mock.MagicMock()
            mock_opener.open.return_value = single_resp

            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_result),
                mock.patch("chroot_distro.helpers.docker.layers._download_segment", side_effect=mock_dl_segment_error),
                mock.patch("chroot_distro.helpers.docker.layers.auth_opener", return_value=mock_opener),
            ):
                result_path = download_blob(
                    repo="library/nextcloud",
                    digest=digest,
                    token="test_token",
                    connections=2,
                )

        assert result_path == path
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            assert f.read() == content

    def test_segmented_resume(self, mock_cache_path, tmp_path):
        digest, path = mock_cache_path
        content = b"A" * (8 * 1024 * 1024)  # 8 MiB (forces 2 segments of 4MiB: 0-4194303, 4194304-8388607)
        import hashlib

        expected_hex = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{expected_hex}"
        path = str(tmp_path / f"layer_{expected_hex}")

        with mock.patch("chroot_distro.helpers.docker.layers.layer_cache_path", return_value=path):
            probe_result = _ProbeResult(
                content_length=len(content),
                final_url="https://cdn.example.com/final.blob",
                range_ok=True,
            )

            # Mock build_opener for 1st run: segment 0 succeeds, segment 1 fails after 1MB
            def mock_open_first(req, *args, **kwargs):
                range_header = req.headers.get("Range", "")
                if range_header == "bytes=0-4194303":
                    return _FakeResp(status=206, body=b"A" * (4 * 1024 * 1024))
                elif range_header == "bytes=4194304-8388607":

                    class BrokenStream:
                        def __init__(self):
                            self.bytes_read = 0

                        def read(self, n):
                            if self.bytes_read >= 1024 * 1024:
                                raise ConnectionResetError("Connection reset by peer")
                            chunk = b"A" * min(n, 1024 * 1024 - self.bytes_read)
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
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_result),
                mock.patch("urllib.request.build_opener", return_value=mock_opener_first),
            ):
                with pytest.raises(Exception):
                    download_blob(
                        repo="library/nextcloud",
                        digest=digest,
                        token="test_token",
                        connections=2,
                    )

            # Ensure temp files and chunks.json exist
            chunks_json = f"{path}.chunks.json"
            assert os.path.isfile(chunks_json)
            assert os.path.isfile(f"{path}.chunk0.tmp")
            assert os.path.isfile(f"{path}.chunk1.tmp")
            assert os.path.getsize(f"{path}.chunk0.tmp") == 4 * 1024 * 1024
            assert os.path.getsize(f"{path}.chunk1.tmp") == 1024 * 1024

            # Second run: resumes. Check that segment 1 is requested with correct range.
            captured_ranges = []

            def mock_open_second(req, *args, **kwargs):
                range_header = req.headers.get("Range", "")
                captured_ranges.append(range_header)
                if range_header == "bytes=5242880-8388607":
                    return _FakeResp(status=206, body=b"A" * (3 * 1024 * 1024))
                else:
                    return _FakeResp(status=200)

            mock_opener_second = mock.MagicMock()
            mock_opener_second.open.side_effect = mock_open_second

            with (
                mock.patch("chroot_distro.helpers.docker.layers._probe_blob", return_value=probe_result),
                mock.patch("urllib.request.build_opener", return_value=mock_opener_second),
            ):
                result_path = download_blob(
                    repo="library/nextcloud",
                    digest=digest,
                    token="test_token",
                    connections=2,
                )

            assert result_path == path
            assert os.path.isfile(path)
            with open(path, "rb") as f:
                assert f.read() == content

            # Check ranges requested during second run: only segment 1 should have been requested.
            assert len(captured_ranges) == 1
            assert captured_ranges[0] == "bytes=5242880-8388607"

            # Check that temp files and chunks.json are cleaned up on success
            assert not os.path.isfile(chunks_json)
            assert not os.path.isfile(f"{path}.chunk0.tmp")
            assert not os.path.isfile(f"{path}.chunk1.tmp")
