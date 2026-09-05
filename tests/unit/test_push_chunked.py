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
