"""Tests for the retry policy that listens to Retry-After and quota headers."""

import email.message
import io
import urllib.error

from chroot_distro.helpers.docker.transport import _relays_docker_hub, rate_limited_msg
from chroot_distro.helpers.download import (
    MAX_RETRY_AFTER,
    is_retryable_http_error,
    retry_after,
    retry_http,
)


def _error(code, url="https://reg.example/v2/", **headers):
    msg = email.message.Message()
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    return urllib.error.HTTPError(url, code, "refused", msg, io.BytesIO(b""))


def test_retry_after_reads_delta_seconds():
    assert retry_after(_error(429, Retry_After="30")) == 30.0


def test_retry_after_reads_an_http_date_in_the_past_as_zero():
    assert retry_after(_error(429, Retry_After="Wed, 21 Oct 2015 07:28:00 GMT")) == 0.0


def test_retry_after_is_none_when_absent_or_unparsable():
    assert retry_after(_error(429)) is None
    assert retry_after(_error(429, Retry_After="soon")) is None
    assert retry_after(TimeoutError()) is None


def test_a_429_past_the_cap_is_not_retried():
    assert not is_retryable_http_error(_error(429, Retry_After=str(MAX_RETRY_AFTER + 1)))
    assert is_retryable_http_error(_error(429, Retry_After=str(MAX_RETRY_AFTER)))


def test_a_429_with_its_quota_spent_is_not_retried():
    assert not is_retryable_http_error(_error(429, RateLimit_Remaining="0;w=3600"))
    assert not is_retryable_http_error(_error(429, X_RateLimit_Remaining="0"))
    assert is_retryable_http_error(_error(429, RateLimit_Remaining="12;w=3600"))
    assert is_retryable_http_error(_error(429))


def test_a_retry_after_on_another_status_decides_nothing():
    # A 500 cannot set the sleep time.
    assert is_retryable_http_error(_error(500, Retry_After=str(MAX_RETRY_AFTER + 1)))


def test_retry_http_waits_what_the_server_asked(monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", slept.append)
    attempts = []

    def _operation():
        attempts.append(1)
        if len(attempts) == 1:
            raise _error(429, Retry_After="7")
        return "ok"

    assert retry_http(_operation, what="t", max_retries=2, retry_delay=0) == "ok"
    assert slept == [7]


def test_relays_docker_hub_needs_the_header_and_the_same_host():
    exc = _error(429, url="https://docker.n8n.io/v2/n8nio/n8n/manifests/latest", Docker_RateLimit_Source="10.0.0.1")
    assert _relays_docker_hub("docker.n8n.io", exc)
    assert not _relays_docker_hub("ghcr.io", exc)
    assert not _relays_docker_hub("docker.n8n.io", _error(429, url="https://docker.n8n.io/v2/"))


def test_rate_limited_message_for_docker_hub(monkeypatch):
    monkeypatch.delenv("CD_DOCKER_AUTH", raising=False)
    text = rate_limited_msg("n8nio/n8n:latest", ("", "library/n8nio/n8n", "latest"), _error(429, Retry_After="120"))
    assert "Docker Hub" in text
    assert "per network address" in text
    assert "about 2 minutes" in text
    assert "CD_DOCKER_AUTH" in text


def test_rate_limited_message_for_an_account(monkeypatch):
    monkeypatch.setenv("CD_DOCKER_AUTH", "user:token")
    text = rate_limited_msg("n8nio/n8n:latest", ("", "library/n8nio/n8n", "latest"), _error(429))
    assert "for the account in CD_DOCKER_AUTH" in text
    assert "Try again later" in text


def test_rate_limited_message_for_a_front_end_names_the_hub_reference(monkeypatch):
    monkeypatch.delenv("CD_DOCKER_AUTH", raising=False)
    exc = _error(429, url="https://docker.n8n.io/v2/n8nio/n8n/manifests/latest", Docker_RateLimit_Source="10.0.0.1")
    text = rate_limited_msg("docker.n8n.io/n8nio/n8n:latest", ("docker.n8n.io", "n8nio/n8n", "latest"), exc)
    assert "passes requests on to Docker Hub" in text
    assert "'n8nio/n8n:latest'" in text
