"""Tests for truncation detection on Content-Length bodies."""

import http.client

import pytest

from chroot_distro.helpers.download import (
    NETWORK_ERRORS,
    IncompleteResponse,
    declared_length,
    require_complete_body,
    retry_http,
)


class _Resp:
    def __init__(self, headers):
        self.headers = headers


def test_declared_length_ignores_unparsable_and_negative():
    assert declared_length(_Resp({"Content-Length": "10"})) == 10
    assert declared_length(_Resp({"Content-Length": "abc"})) == 0
    assert declared_length(_Resp({"Content-Length": "-5"})) == 0
    assert declared_length(_Resp({})) == 0


def test_require_complete_body():
    require_complete_body(10, 10)
    require_complete_body(10, 0)
    with pytest.raises(IncompleteResponse):
        require_complete_body(5, 10, "Manifest")


def test_incomplete_response_is_a_network_error_and_is_retried():
    assert issubclass(IncompleteResponse, http.client.HTTPException)
    assert NETWORK_ERRORS[-1] is http.client.HTTPException

    calls = []

    def _operation():
        calls.append(1)
        if len(calls) == 1:
            raise IncompleteResponse("short")
        return "ok"

    assert retry_http(_operation, what="t", max_retries=2, retry_delay=0) == "ok"
    assert len(calls) == 2
