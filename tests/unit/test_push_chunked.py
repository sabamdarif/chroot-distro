"""Tests for push retry/chunked-upload helper logic."""

import io
import urllib.error
from unittest.mock import patch

import pytest

from chroot_distro.helpers.docker import push


class _Response:
    def __init__(self, status, url, headers=None):
        self.status = status
        self.url = url
        self.headers = headers or {}

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_range_end_parses_offset():
    assert push._range_end("0-1023") == 1023
    assert push._range_end("bytes=0-99") == 99
    assert push._range_end("") is None
    assert push._range_end("garbage") is None
    assert push._range_end("9-10") is None
    assert push._range_end("0-" + "9" * 20) is None


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

    class Opener:
        def open(self, req, **_kwargs):
            sent.append((req.get_method(), req.full_url, req.get_header("Authorization")))
            if req.get_method() == "POST":
                return _Response(202, base + "/effective/uploads/", {"Location": "session"})
            if req.get_header("Content-range") == "0-1":
                return _Response(202, "https://storage.example/session", {"Location": f"?{signed}", "Range": "0-1"})
            if req.get_method() == "PUT":
                return _Response(201, req.full_url)
            return _Response(202, req.full_url, {"Range": "0-3"})

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 2)
    with blob.open("rb") as source:
        push._upload_blob_chunked(base, "repo", "sha256:test", source, {"Authorization": "Basic fixture"}, 4, "blob")

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


@pytest.mark.parametrize("http_status", [None, 416, 429])
def test_failed_patch_checks_status_and_resumes_only_confirmed_bytes(monkeypatch, http_status):
    from chroot_distro.helpers import download

    base = "https://reg.example"
    upload_url = base + "/effective/session"
    storage_url = "https://storage.example/session?state=%2F+%20"
    digest = "sha256:" + "a" * 64
    sent, delays, stored = [], [], bytearray()
    committed = False

    class Opener:
        def open(self, req, **_kwargs):
            nonlocal committed
            method, url = req.get_method(), req.full_url
            sent.append((method, url, req.get_header("Content-range"), req.get_header("Authorization")))
            if method == "POST":
                return _Response(202, base + "/start", {"Location": upload_url})
            if method == "GET":
                return _Response(204, url, {"Range": "0-1", "Location": storage_url})
            if method == "PATCH":
                start, end = map(int, req.get_header("Content-range").split("-"))
                assert start == len(stored)
                if not stored:
                    stored.extend(req.data[:2])
                    if http_status is None:
                        raise ConnectionResetError
                    headers = {"Retry-After": "11"} if http_status == 429 else {}
                    raise urllib.error.HTTPError(url, http_status, "ignored fixture", headers, None)
                stored.extend(req.data)
                assert len(stored) == end + 1
                return _Response(202, url, {"Range": f"0-{end}"})
            if method == "PUT":
                assert bytes(stored) == b"abcdef"
                committed = True
                raise ConnectionResetError
            assert method == "HEAD"
            assert committed
            return _Response(200, url)

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 3)
    monkeypatch.setattr(push, "_push_max_retries", lambda: 1)
    monkeypatch.setattr(download.time, "sleep", delays.append)

    push._upload_blob_chunked(base, "repo", digest, io.BytesIO(b"abcdef"), {"Authorization": "Basic fixture"}, 6, "blob")

    assert sent == [
        ("POST", base + "/v2/repo/blobs/uploads/", None, "Basic fixture"),
        ("PATCH", upload_url, "0-2", "Basic fixture"),
        ("GET", upload_url, None, "Basic fixture"),
        ("PATCH", storage_url, "2-4", None),
        ("PATCH", storage_url, "5-5", None),
        ("PUT", f"{storage_url}&digest=sha256%3A{'a' * 64}", None, None),
        ("HEAD", base + "/v2/repo/blobs/" + digest, None, "Basic fixture"),
    ]
    assert delays == [11 if http_status == 429 else 5, 5]


@pytest.mark.parametrize("range_header", ["", "1-1", "0-9", "0-0"])
def test_malformed_patch_acknowledgment_stops_the_upload(monkeypatch, range_header):
    base = "https://reg.example"
    methods = []

    class Opener:
        def open(self, req, **_kwargs):
            methods.append(req.get_method())
            if methods == ["POST"]:
                return _Response(202, req.full_url, {"Location": base + "/session"})
            assert methods == ["POST", "PATCH"]
            return _Response(202, req.full_url, {"Range": range_header})

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 2)
    with pytest.raises(RuntimeError, match="acknowledge the full upload chunk"):
        push._upload_blob_chunked(base, "repo", "sha256:test", io.BytesIO(b"ab"), {}, 2, "blob")
    assert methods == ["POST", "PATCH"]


def test_ambiguous_initial_status_creates_a_retry_session(monkeypatch):
    from chroot_distro.helpers import download

    base = "https://reg.example"
    routes = [
        ("POST", _Response(202, base, {"Location": "/old"})),
        ("PATCH", TimeoutError()),
        ("GET", _Response(204, base, {"Range": "0-0", "Location": "/old"})),
        ("POST", _Response(202, base, {"Location": "/new"})),
        ("PATCH", _Response(202, base, {"Range": "0-1"})),
        ("PUT", _Response(201, base)),
    ]

    class Opener:
        def open(self, req, **_kwargs):
            method, response = routes.pop(0)
            assert req.get_method() == method
            if method == "PATCH":
                assert req.get_header("Content-range") == "0-1"
                assert req.data == b"ab"
            if isinstance(response, Exception):
                raise response
            if method in ("PATCH", "PUT"):
                assert req.full_url.startswith(base + "/new")
            return response

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 2)
    monkeypatch.setattr(download.time, "sleep", lambda _delay: None)
    push._upload_blob_chunked(base, "repo", "sha256:test", io.BytesIO(b"ab"), {}, 2, "blob")
    assert not routes


@pytest.mark.parametrize("committed", [False, True])
def test_lost_final_response_checks_blob_even_when_retries_are_exhausted(monkeypatch, committed):
    base = "https://reg.example"
    digest = "sha256:" + "a" * 64
    methods = []

    class Opener:
        def open(self, req, **_kwargs):
            method = req.get_method()
            methods.append(method)
            if method == "POST":
                return _Response(202, req.full_url, {"Location": "/upload"})
            if method == "PATCH":
                return _Response(202, req.full_url, {"Range": "0-1"})
            if method == "PUT":
                raise TimeoutError
            assert method == "HEAD"
            assert req.full_url == base + "/v2/repo/blobs/" + digest
            if not committed:
                raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)
            return _Response(200, req.full_url)

    monkeypatch.setattr(push, "auth_opener", Opener)
    monkeypatch.setattr(push, "_push_chunk_size", lambda: 2)
    monkeypatch.setattr(push, "_push_max_retries", lambda: 0)
    source = io.BytesIO(b"ab")
    if committed:
        push._upload_blob_chunked(base, "repo", digest, source, {}, 2, "blob")
    else:
        with pytest.raises(TimeoutError):
            push._upload_blob_chunked(base, "repo", digest, source, {}, 2, "blob")
    assert methods == ["POST", "PATCH", "PUT", "HEAD"]
