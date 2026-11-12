# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The redirect policy every opener in the program is built with.

Driven through a real opener from download.http_opener(): a canned handler
sits in front of the HTTP(S) handlers and answers from a route table, so the
redirect travels urllib's whole error-processing chain, the path a live 302
takes, without a socket being opened.
"""

import email.message
import io
import urllib.error
import urllib.request
import urllib.response

import pytest

from chroot_distro.helpers import download


class _Canned(urllib.request.BaseHandler):
    handler_order = 100  # ahead of HTTPHandler/HTTPSHandler

    def __init__(self, routes):
        self.routes = routes
        self.seen = []
        self.bodies = []

    def _answer(self, req):
        self.seen.append(req.full_url)
        code, location, body = self.routes[req.full_url]
        headers = email.message.Message()
        if location is not None:
            headers["Location"] = location
        headers["Content-Length"] = str(len(body))
        fp = io.BytesIO(body)
        self.bodies.append(fp)
        resp = urllib.response.addinfourl(fp, headers, req.full_url, code)
        resp.msg = "Found" if 300 <= code < 400 else "OK"
        return resp

    http_open = https_open = _answer


def _open_through(routes, url, **opener_kw):
    canned = _Canned(routes)
    opener = download.http_opener(**opener_kw)
    opener.add_handler(canned)
    try:
        with opener.open(url) as resp:
            return canned, resp.read()
    except BaseException as exc:
        exc.canned = canned
        raise


def test_https_to_http_redirect_is_refused():
    routes = {
        "https://a.example/x.tar": (302, "http://b.example/x.tar", b""),
        "http://b.example/x.tar": (200, None, b"tampered"),
    }
    with pytest.raises(download.RedirectRefused) as exc:
        _open_through(routes, "https://a.example/x.tar")
    assert exc.value.plaintext
    assert "plain HTTP" in str(exc.value)
    # Refused before the plaintext hop was ever requested, and the 3xx
    # response's connection was released rather than left open.
    assert exc.value.canned.seen == ["https://a.example/x.tar"]
    assert exc.value.canned.bodies[0].closed


def test_https_to_http_redirect_is_followed_under_insecure():
    routes = {
        "https://a.example/x.tar": (302, "http://b.example/x.tar", b""),
        "http://b.example/x.tar": (200, None, b"payload"),
    }
    canned, body = _open_through(routes, "https://a.example/x.tar", insecure=True)
    assert body == b"payload"
    assert canned.seen[-1] == "http://b.example/x.tar"


@pytest.mark.parametrize(
    "start,location,final",
    [
        # An upgrade, and what the user already chose, are both followed.
        ("http://a.example/x", "https://b.example/x", "https://b.example/x"),
        ("http://a.example/x", "http://b.example/x", "http://b.example/x"),
        ("https://a.example/x", "https://cdn.example/x", "https://cdn.example/x"),
        # Relative and scheme-relative targets keep the scheme they came from.
        ("https://a.example/v2/x", "/blobs/y", "https://a.example/blobs/y"),
        ("https://a.example/x", "//cdn.example/y", "https://cdn.example/y"),
    ],
)
def test_redirects_that_keep_or_gain_tls_are_followed(start, location, final):
    routes = {start: (302, location, b""), final: (200, None, b"ok")}
    canned, body = _open_through(routes, start)
    assert body == b"ok"
    assert canned.seen == [start, final]


@pytest.mark.parametrize(
    "location",
    [
        "ftp://b.example/x.tar",  # urllib's own handler would follow it
        "file:///etc/passwd",
        "data:,hello",
        "gopher://b.example/x",
        "https:///no-host",  # a scheme change naming no host
    ],
)
@pytest.mark.parametrize("insecure", [False, True])
def test_redirects_off_http_are_refused(location, insecure):
    # Never retried: the stdlib's own refusal was an HTTPError carrying
    # the 3xx, which retry_http reads as transient and repeated.
    routes = {"http://a.example/x.tar": (302, location, b"")}
    with pytest.raises(download.RedirectRefused) as exc:
        _open_through(routes, "http://a.example/x.tar", insecure=insecure)
    assert not exc.value.plaintext
    assert not download.is_retryable_http_error(exc.value)


@pytest.mark.parametrize("location", ["http://[/x", "https://[::1/x"])
def test_a_malformed_location_is_a_refusal_not_a_value_error(location):
    # urllib parses the header on the way to following it, and its
    # ValueError came out of the middle of the request as a traceback.
    routes = {"https://a.example/x": (301, location, b"")}
    with pytest.raises(download.RedirectRefused) as exc:
        _open_through(routes, "https://a.example/x")
    assert "not a valid URL" in str(exc.value)


def test_a_redirect_target_is_quoted_in_the_message():
    # The Location header is the server's text and goes to the terminal.
    routes = {"https://a.example/x": (302, "http://b.example/\x1b[2J", b"")}
    with pytest.raises(download.RedirectRefused) as exc:
        _open_through(routes, "https://a.example/x")
    assert "\x1b" not in str(exc.value)


def test_the_opener_speaks_only_http_and_https():
    for url in ("file:///etc/passwd", "ftp://a.example/x", "data:,hi"):
        with pytest.raises(urllib.error.URLError, match="unknown url type"):
            download.http_opener().open(url)


def test_download_file_refused_downgrade_names_the_remedy(tmp_path, monkeypatch):
    calls = []

    class _FakeOpener:
        def open(self, req, *_a, **_k):
            calls.append(req.full_url)
            raise download.RedirectRefused("Refusing to follow ...", plaintext=True)

    monkeypatch.setattr(download, "http_opener", lambda **_k: _FakeOpener())
    dest = tmp_path / "rootfs.tar"
    with pytest.raises(RuntimeError) as exc:
        download.download_file("https://example.com/rootfs.tar", str(dest), max_retries=5, retry_delay=0)
    assert "--allow-insecure" in str(exc.value)
    assert len(calls) == 1
    assert not dest.exists()


def test_download_file_refused_scheme_offers_no_flag(tmp_path, monkeypatch):
    # --allow-insecure does not permit ftp://, so it is not suggested.
    class _FakeOpener:
        def open(self, *_a, **_k):
            raise download.RedirectRefused("Refusing to follow ...")

    monkeypatch.setattr(download, "http_opener", lambda **_k: _FakeOpener())
    with pytest.raises(RuntimeError) as exc:
        download.download_file("https://example.com/rootfs.tar", str(tmp_path / "o"), retry_delay=0)
    assert "--allow-insecure" not in str(exc.value)
