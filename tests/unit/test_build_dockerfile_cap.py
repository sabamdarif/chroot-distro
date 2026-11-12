"""Tests for the ceiling `build` puts on a Dockerfile it reads whole."""

import io

from chroot_distro.commands import build as build_mod
from chroot_distro.helpers.dockerfile import MAX_DOCKERFILE_BYTES


def test_read_dockerfile_returns_the_bytes(tmp_path):
    path = tmp_path / "Dockerfile"
    path.write_bytes(b"FROM scratch\r\n")
    assert build_mod._read_dockerfile(str(path)) == b"FROM scratch\r\n"


def test_read_dockerfile_refuses_one_byte_over_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(build_mod, "MAX_DOCKERFILE_BYTES", 8)
    path = tmp_path / "Dockerfile"
    path.write_bytes(b"x" * 9)
    assert build_mod._read_dockerfile(str(path)) is None


def test_read_dockerfile_accepts_exactly_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(build_mod, "MAX_DOCKERFILE_BYTES", 8)
    path = tmp_path / "Dockerfile"
    path.write_bytes(b"x" * 8)
    assert build_mod._read_dockerfile(str(path)) == b"x" * 8


def test_read_dockerfile_reads_stdin_as_bytes(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"FROM scratch\r\n")))
    monkeypatch.setattr(build_mod, "MAX_DOCKERFILE_BYTES", MAX_DOCKERFILE_BYTES)
    assert build_mod._read_dockerfile("-") == b"FROM scratch\r\n"


def test_read_dockerfile_refuses_a_large_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"x" * 9)))
    monkeypatch.setattr(build_mod, "MAX_DOCKERFILE_BYTES", 8)
    assert build_mod._read_dockerfile("-") is None


def test_the_shared_cap_is_sixteen_mebibytes():
    assert MAX_DOCKERFILE_BYTES == 16 * 1024 * 1024
