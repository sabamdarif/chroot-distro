"""Tests for the registry transport's TLS policy and HTTP opener."""

import urllib.request

from chroot_distro.helpers.docker.transport import insecure_for
from chroot_distro.helpers.download import NETWORK_TIMEOUT, _Opener


def test_insecure_for_never_reaches_docker_hub():
    assert insecure_for("", True) is False
    assert insecure_for("ghcr.io", True) is True
    assert insecure_for("ghcr.io", False) is False
    assert insecure_for("localhost:5000", True) is True


def test_opener_applies_a_default_timeout(monkeypatch):
    seen = []

    def _open(self, fullurl, data=None, timeout=None):
        seen.append(timeout)
        return "response"

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _open)
    opener = _Opener()
    assert opener.open("https://reg.example") == "response"
    assert seen[-1] == NETWORK_TIMEOUT
    opener.open("https://reg.example", timeout=5)
    assert seen[-1] == 5



class _Resp:
    def __init__(self, body=b"", headers=None):
        self._body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def read(self, *_a):
        return self._body


def _opener_raising(exc):
    class _Opener:
        def open(self, _req, timeout=None):
            raise exc

    return _Opener()


def _challenge(value):
    import email.message
    import urllib.error

    msg = email.message.Message()
    msg["WWW-Authenticate"] = value
    return urllib.error.HTTPError("https://reg.example/v2/", 401, "unauthorized", msg, None)


def test_basic_challenge_returns_the_credentials(monkeypatch):
    import base64

    from chroot_distro.helpers.docker import transport

    monkeypatch.setenv("CD_DOCKER_AUTH", "user:pass")

    class _Opener:
        def open(self, req, timeout=None):
            if req.get_header("Authorization"):
                return _Resp()
            raise _challenge('Basic realm="registry"')

    monkeypatch.setattr(transport, "opener", lambda *_a, **_k: _Opener())

    auth, base = transport.get_auth_token("private/repo", "reg.example")

    assert auth == "Basic " + base64.b64encode(b"user:pass").decode()
    assert base == "https://reg.example"


def test_bearer_token_carries_its_prefix(monkeypatch):
    from chroot_distro.helpers.docker import transport

    monkeypatch.delenv("CD_DOCKER_AUTH", raising=False)

    class _Opener:
        def open(self, req, timeout=None):
            if "/v2/" in req.full_url:
                raise _challenge('Bearer realm="https://auth.example/token",service="reg"')
            return _Resp(b'{"token": "abc123"}', {"Content-Type": "application/json"})

    monkeypatch.setattr(transport, "opener", lambda *_a, **_k: _Opener())

    auth, base = transport.get_auth_token("repo", "reg.example")
    assert auth == "Bearer abc123"
    assert base == "https://reg.example"


def test_an_open_registry_gets_no_credential(monkeypatch):
    from chroot_distro.helpers.docker import transport

    monkeypatch.delenv("CD_DOCKER_AUTH", raising=False)
    monkeypatch.setattr(transport, "opener", lambda *_a, **_k: _opener_raising(_challenge("Negotiate")))

    assert transport.get_auth_token("repo", "reg.example") == ("", "https://reg.example")


def test_credentials_check_names_no_repository(monkeypatch):
    import base64

    from chroot_distro.helpers.docker import transport

    seen = []

    class _Opener:
        def open(self, *_a, **_k):
            raise AssertionError("the request body is patched out")

    monkeypatch.setenv("CD_DOCKER_AUTH", "user:pass")
    monkeypatch.setattr(transport, "auth_opener", lambda: _Opener())
    monkeypatch.setattr(transport, "_request_body", lambda *_a, **_k: b'{"token": "abc"}')
    monkeypatch.setattr(
        transport, "_check_credentials", lambda open_fn, url, basic, registry, rejected: seen.append((url, basic, rejected))
    )

    auth, base = transport.get_auth_token("private/repo", "")

    assert auth == "Bearer abc"
    assert seen == [
        (
            transport._token_url(transport.AUTH_URL, transport.HUB_SERVICE),
            "Basic " + base64.b64encode(b"user:pass").decode(),
            transport._REJECTED_BY_TOKEN_SERVICE,
        )
    ]


def test_check_credentials_reports_a_refusal_without_the_password(monkeypatch):
    import email.message
    import urllib.error

    import pytest

    from chroot_distro.helpers.docker import transport

    msg = email.message.Message()
    exc = urllib.error.HTTPError("https://reg.example/v2/", 403, "forbidden", msg, None)
    monkeypatch.setattr(transport, "_request_body", lambda *_a, **_k: (_ for _ in ()).throw(exc))

    with pytest.raises(RuntimeError) as caught:
        transport._check_credentials(lambda *_a: None, "https://reg.example/v2/", "Basic dXNlcjpwYXNz", "reg.example", (401, 403))

    text = str(caught.value)
    assert "rejected the credentials in CD_DOCKER_AUTH (HTTP 403)" in text
    assert "dXNlcjpwYXNz" not in text


def test_plaintext_and_off_origin_challenges_cannot_send_credentials(monkeypatch):
    import io
    import urllib.error

    import pytest

    from chroot_distro.helpers.docker import transport
    from chroot_distro.helpers.download import RedirectRefused

    monkeypatch.setenv("CD_DOCKER_AUTH", "user:secret")
    for origin, realm, failure in (
        ("https://reg.example/v2/", "http://auth.example/token?secret=fixture", RedirectRefused),
        ("https://other.example/v2/", "https://auth.example/token", RuntimeError),
        ("https://reg.example/v2/", "https:relative", RedirectRefused),
        ("https://reg.example/v2/", "https://auth.example%3A443/token", RedirectRefused),
    ):
        probe_body = io.BytesIO()
        error = urllib.error.HTTPError(
            origin, 401, "Unauthorized", {"WWW-Authenticate": f'Bearer realm="{realm}"'}, probe_body,
        )
        requests = []

        def request(_open, req, _what):
            requests.append(req)
            raise error

        monkeypatch.setattr(transport, "_request_body", request)
        with pytest.raises(failure) as caught:
            transport.get_auth_token("repo", "reg.example")
        assert "secret=fixture" not in str(caught.value)
        assert probe_body.closed
        assert [req.get_header("Authorization") for req in requests] == [None]


def test_upgraded_basic_challenge_uses_effective_https_url(monkeypatch):
    import urllib.error

    from chroot_distro.helpers.docker import transport

    monkeypatch.setenv("CD_DOCKER_AUTH", "user:pass")
    requests = []
    effective = "https://reg.example/check"

    def request(_open, req, _what):
        requests.append((req.full_url, req.get_header("Authorization")))
        if req.full_url == "https://reg.example/v2/":
            raise urllib.error.URLError("fixture plaintext reply")
        if req.full_url == "http://reg.example/v2/":
            raise urllib.error.HTTPError(
                effective, 401, "Unauthorized", {"WWW-Authenticate": "Basic realm=registry"}, None,
            )
        return b""

    monkeypatch.setattr(transport, "_request_body", request)
    monkeypatch.setattr(transport, "is_plaintext_http_tls_error", lambda _exc: True)
    auth, base = transport.get_auth_token("repo", "reg.example", insecure=True)
    assert base == "https://reg.example"
    assert auth.startswith("Basic ")
    assert requests == [
        ("https://reg.example/v2/", None), ("http://reg.example/v2/", None), (effective, auth),
    ]
