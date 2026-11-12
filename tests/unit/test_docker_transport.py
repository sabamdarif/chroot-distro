"""Tests for the registry transport's TLS policy."""

from chroot_distro.helpers.docker.transport import insecure_for


def test_insecure_for_never_reaches_docker_hub():
    assert insecure_for("", True) is False
    assert insecure_for("ghcr.io", True) is True
    assert insecure_for("ghcr.io", False) is False
    assert insecure_for("localhost:5000", True) is True
