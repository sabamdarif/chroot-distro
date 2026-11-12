"""Tests for credential scoping across redirects and upload Locations."""

from chroot_distro.helpers.docker.push import _headers_for
from chroot_distro.helpers.docker.transport import same_auth_origin


def test_same_auth_origin():
    assert same_auth_origin("https://reg.example", "https://reg.example/upload/1")
    assert same_auth_origin("http://reg.example:80", "https://reg.example")
    assert not same_auth_origin("https://reg.example", "http://reg.example")
    assert not same_auth_origin("https://reg.example", "https://reg.example:8443")
    assert not same_auth_origin("https://reg.example", "https://evil.example")
    assert not same_auth_origin("https://reg.example", "https://[bad")


def test_headers_for_drops_token_off_origin():
    headers = {"Authorization": "Bearer TKN", "User-Agent": "x"}
    kept = _headers_for(headers, "https://reg.example", "https://reg.example/upload/1")
    assert kept["Authorization"] == "Bearer TKN"
    dropped = _headers_for(headers, "https://reg.example", "https://evil.example/upload/1")
    assert "Authorization" not in dropped
    assert dropped["User-Agent"] == "x"
