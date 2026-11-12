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


# ----- the redirect policy the registry opener carries --------------------

import urllib.request

import pytest

from chroot_distro.helpers.docker import transport
from chroot_distro.helpers.download import RedirectRefused


def _make_redirect(orig_url, new_url, allow_plaintext=False):
    handler = transport.AuthStrippingRedirectHandler(allow_plaintext=allow_plaintext)
    req = urllib.request.Request(
        orig_url,
        headers={"Authorization": "Bearer TOKEN", "User-Agent": "cd"},
    )
    return handler.redirect_request(req, None, 302, "Found", {}, new_url)


def test_redirect_off_https_is_refused_without_insecure():
    # The registry answered a TLS request with a way around TLS, and a tag's
    # manifest has no digest to catch what the plaintext hop serves.
    with pytest.raises(RedirectRefused) as exc:
        _make_redirect(
            "https://reg.example/v2/foo/manifests/latest",
            "http://reg.example/v2/foo/manifests/latest",
        )
    assert exc.value.plaintext


def test_redirect_off_https_still_strips_the_header_when_followed():
    # Only --allow-insecure follows such a redirect at all, and even then
    # the credential does not go with it.
    new_req = _make_redirect(
        "https://reg.example/v2/foo/blobs/sha256:aa",
        "http://reg.example/v2/foo/blobs/sha256:aa",
        allow_plaintext=True,
    )
    assert new_req.get_header("Authorization") is None


def test_redirect_to_ftp_is_refused_even_under_insecure():
    with pytest.raises(RedirectRefused) as exc:
        _make_redirect(
            "http://reg.example/v2/foo/blobs/sha256:aa",
            "ftp://cdn.example/blob",
            allow_plaintext=True,
        )
    assert not exc.value.plaintext


@pytest.mark.parametrize("insecure", [False, True])
def test_registry_openers_carry_the_policy(insecure):
    op = transport.opener(insecure)
    handlers = [h for h in op.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert len(handlers) == 1
    assert isinstance(handlers[0], transport.AuthStrippingRedirectHandler)
    assert handlers[0].allow_plaintext is insecure
