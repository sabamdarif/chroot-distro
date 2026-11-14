"""Tests for push retry/chunked-upload helper logic."""

import urllib.error
from unittest.mock import patch

import pytest

from chroot_distro.helpers.docker import push


def test_range_end_parses_offset():
    assert push._range_end("0-1023") == 1023
    assert push._range_end("bytes=0-99") == 99
    assert push._range_end("") is None
    assert push._range_end("garbage") is None


def test_with_digest_appends_query():
    assert push._with_digest("https://r/v2/x/blobs/uploads/abc", "sha256:d") == (
        "https://r/v2/x/blobs/uploads/abc?digest=sha256%3Ad"
    )
    assert push._with_digest("https://r/upload?state=1", "sha256:d") == ("https://r/upload?state=1&digest=sha256%3Ad")


def test_is_retryable():
    assert push._is_retryable(urllib.error.HTTPError("u", 500, "e", {}, None))
    assert push._is_retryable(urllib.error.HTTPError("u", 429, "e", {}, None))
    assert not push._is_retryable(urllib.error.HTTPError("u", 404, "e", {}, None))
    assert push._is_retryable(ConnectionResetError())
    assert push._is_retryable(TimeoutError())
    assert not push._is_retryable(ValueError("nope"))


def test_push_chunk_size_env_override(monkeypatch):
    monkeypatch.setenv("CD_PUSH_CHUNK_SIZE", "4096")
    assert push._push_chunk_size() == 4096
    monkeypatch.setenv("CD_PUSH_CHUNK_SIZE", "0")
    assert push._push_chunk_size() == push._DEFAULT_PUSH_CHUNK_SIZE
    monkeypatch.delenv("CD_PUSH_CHUNK_SIZE", raising=False)
    assert push._push_chunk_size() == push._DEFAULT_PUSH_CHUNK_SIZE


def test_with_retry_succeeds_after_transient():
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionResetError()
        return "ok"

    with patch.object(push, "_push_max_retries", return_value=5), patch("time.sleep"):
        assert push._with_retry(op, "thing") == "ok"
    assert calls["n"] == 3


def test_with_retry_reraises_non_transient():
    def op():
        raise ValueError("fatal")

    with patch.object(push, "_push_max_retries", return_value=3), patch("time.sleep"), pytest.raises(ValueError):
        push._with_retry(op, "thing")


def test_with_retry_gives_up_after_max():
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        raise TimeoutError()

    with patch.object(push, "_push_max_retries", return_value=2), patch("time.sleep"), pytest.raises(TimeoutError):
        push._with_retry(op, "thing")
    assert calls["n"] == 3  # initial + 2 retries


def test_upload_locations_follow_effective_response_and_keep_opaque_query(tmp_path, monkeypatch):
    base = "https://reg.example"
    sent = []
    blob = tmp_path / "blob"
    blob.write_bytes(b"abcd")
    signed = "sig=%2F+%20&x=1&x=2"

    class Response:
        status = 202

        def __init__(self, url, headers):
            self.url = url
            self.headers = headers

        def geturl(self):
            return self.url

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def open(self, req, **_kwargs):
            sent.append((req.get_method(), req.full_url, req.get_header("Authorization")))
            if req.get_method() == "POST":
                return Response(base + "/effective/uploads/", {"Location": "session"})
            if req.get_header("Content-range") == "0-1":
                return Response("https://storage.example/session", {"Location": f"?{signed}", "Range": "0-1"})
            return Response(req.full_url, {"Range": "0-3"})

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 2)
    push._upload_blob_chunked(base, "repo", "sha256:test", str(blob), {"Authorization": "Basic fixture"}, 4, "blob")

    assert sent == [
        ("POST", base + "/v2/repo/blobs/uploads/", "Basic fixture"),
        ("PATCH", base + "/effective/uploads/session", "Basic fixture"),
        ("PATCH", f"https://storage.example/session?{signed}", None),
        ("PUT", f"https://storage.example/session?{signed}&digest=sha256%3Atest", None),
    ]


def test_upload_location_refuses_plaintext_and_redacts_signed_urls():
    from chroot_distro.helpers.download import RedirectRefused

    base = "https://reg.example"
    target = "http://storage.example/upload?sig=fixture"
    with pytest.raises(RedirectRefused) as caught:
        push._resolve_upload_url(base, base + "/old?sig=previous", target, insecure=False)
    assert caught.value.plaintext
    assert "sig=" not in str(caught.value)
    assert push._resolve_upload_url(base, base, target, insecure=True) == target
    assert "Authorization" not in push._headers_for({"Authorization": "Basic fixture"}, base, target)


def test_explicit_empty_upload_query_replaces_previous_query():
    base = "https://reg.example"
    url = push._resolve_upload_url(base, base + "/upload?sig=previous", "?", insecure=False)
    assert url == base + "/upload?"
    assert push._with_digest(url, "sha256:test") == base + "/upload?digest=sha256%3Atest"
