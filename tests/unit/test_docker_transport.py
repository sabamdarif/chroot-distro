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

