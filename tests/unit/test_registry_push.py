# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Verify what the push command sends for images produced by build."""

import hashlib
import json
import sys
import urllib.error
import urllib.parse
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import cli, message
from chroot_distro.arch import Platform
from chroot_distro.commands import build as build_cmd
from chroot_distro.commands import push as push_cmd
from chroot_distro.helpers.docker import cache, push
from chroot_distro.helpers.oci_writer import build_manifest_and_config

BASE = "https://registry.example"
REF = "registry.example/project/image"
REPO = "/v2/project/image"
PLATFORM = Platform("linux", "amd64")


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture(params=[False, True], ids=["linux-layout", "termux-layout"])
def registry(tmp_path, monkeypatch, request):
    runtime = tmp_path / "runtime"
    cache_dir = runtime / "cache" if request.param else tmp_path / "cache"
    layers_dir = cache_dir / "oci_layers"
    layers_dir.mkdir(parents=True)
    manifests_dir = cache_dir / "oci_manifests"
    manifests_dir.mkdir()
    monkeypatch.setattr(cache, "LAYER_CACHE_DIR", str(layers_dir))
    monkeypatch.setattr(cache, "MANIFEST_CACHE_DIR", str(manifests_dir))
    monkeypatch.setattr(push, "IS_TERMUX", request.param)
    monkeypatch.setattr(push, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(push, "BASE_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(push, "LAYER_CACHE_DIR", str(layers_dir))
    monkeypatch.setattr(build_cmd, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(build_cmd, "get_device_platform", lambda: PLATFORM)
    monkeypatch.setattr(build_cmd, "build_cache_max", lambda: 0)
    monkeypatch.setattr(cli, "_ensure_root_user", lambda _args: None)
    monkeypatch.setattr(message, "_quiet", False)

    def lock(ref, arch, **_kwargs):
        context = nullcontext()
        context.lock_path = f"{ref}/{arch}"
        return context

    monkeypatch.setattr(build_cmd, "BuildLock", lock)
    monkeypatch.setattr(push_cmd, "BuildLock", lock)
    authenticate = Mock(return_value=("Bearer fixture", BASE))
    monkeypatch.setattr(push, "get_auth_token", authenticate)

    blobs, manifests, events = {}, [], []
    before_receiving_blob = Mock()
    session = REPO + "/blobs/uploads/session"

    def open_request(req, **_kwargs):
        assert req.get_header("Authorization") == "Bearer fixture"
        url = urllib.parse.urlsplit(req.full_url)
        method = req.get_method()
        events.append((method, url.path))

        def response(status, **headers):
            return nullcontext(SimpleNamespace(status=status, headers=headers, geturl=lambda: req.full_url))

        if method == "HEAD":
            digest = url.path.rsplit("/", 1)[-1]
            if digest in blobs:
                return response(200)
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        if method == "POST":
            return response(202, Location=session)
        assert method == "PUT"
        if url.path == session:
            digest = urllib.parse.parse_qs(url.query)["digest"][0]
            before_receiving_blob(digest)
            data = req.data if isinstance(req.data, bytes) else req.data.read()
            assert digest == _digest(data)
            blobs[digest] = data
            return response(201)
        assert url.path == REPO + "/manifests/latest"
        manifest = json.loads(req.data)
        assert manifest["config"]["digest"] in blobs
        assert all(layer["digest"] in blobs for layer in manifest["layers"])
        manifests.append(manifest)
        return response(201, **{"Docker-Content-Digest": _digest(req.data)})

    monkeypatch.setattr(push, "auth_opener", lambda: SimpleNamespace(open=open_request))

    def run_cli(*args):
        monkeypatch.setattr(sys, "argv", ["chroot-distro", *args])
        cli.main()

    return SimpleNamespace(
        blobs=blobs, manifests=manifests, events=events, run_cli=run_cli, authenticate=authenticate,
        layers_dir=layers_dir, before_receiving_blob=before_receiving_blob,
    )


def test_scratch_matrix_pushes_one_selected_platform_per_architecture(registry, tmp_path):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\nENV EXAMPLE=fixture\n")
    registry.run_cli("build", "--platform", "linux/amd64,linux/arm64", "-t", REF, str(context))

    for arch in ["x86_64", "linux/arm64"]:
        registry.run_cli("push", "-a", arch, REF)

    assert len(registry.manifests) == 2
    for manifest, arch in zip(registry.manifests, ("amd64", "arm64"), strict=True):
        config = json.loads(registry.blobs[manifest["config"]["digest"]])
        assert manifest["layers"] == []
        assert config["architecture"] == arch
        assert config["rootfs"]["diff_ids"] == []
        assert config["config"]["Env"] == ["EXAMPLE=fixture"]
    assert [event for event in registry.events if "/manifests/" in event[1]] == [
        ("PUT", REPO + "/manifests/latest"),
        ("PUT", REPO + "/manifests/latest"),
    ]


def _layer_image(data):
    digest = _digest(data)
    layer = {"digest": digest, "size": len(data), "diff_id": digest}
    manifest, config = build_manifest_and_config({}, [layer, layer], PLATFORM)
    cache.save_manifest_cache(REF, PLATFORM, manifest, "project/image", config)
    return digest, Path(cache.layer_cache_path(digest))


def test_push_sends_a_verified_snapshot_and_keeps_duplicate_manifest_positions(registry):
    original = b"fixture layer"
    digest, path = _layer_image(original)
    path.write_bytes(original)

    def change_cache(receiving):
        if receiving == digest:
            path.write_bytes(b"changed layer")

    registry.before_receiving_blob.side_effect = change_cache
    registry.run_cli("push", "-a", "amd64", REF)
    assert registry.blobs[digest] == original
    assert [entry["digest"] for entry in registry.manifests[0]["layers"]] == [digest, digest]
    assert registry.events.count(("HEAD", REPO + "/blobs/" + digest)) == 1


def test_push_refuses_same_size_corrupt_layer_before_upload(registry, capsys):
    _, path = _layer_image(b"first")
    path.write_bytes(b"wrong")
    with pytest.raises(SystemExit) as caught:
        registry.run_cli("push", "-a", "amd64", REF)
    assert caught.value.code == 1
    assert "Cached layer digest mismatch" in capsys.readouterr().err
    assert [method for method, _ in registry.events] == ["HEAD"]


def test_push_refuses_a_layer_symlink_before_authentication(registry, tmp_path, capsys):
    data = b"fixture"
    _, path = _layer_image(data)
    source = tmp_path / "fixture"
    source.write_bytes(data)
    path.symlink_to(source)
    with pytest.raises(SystemExit):
        registry.run_cli("push", "-a", "amd64", REF)
    assert "not a regular cache file" in capsys.readouterr().err
    registry.authenticate.assert_not_called()


def test_push_rejects_a_config_size_mismatch_before_authentication(registry, capsys):
    manifest, config = build_manifest_and_config({}, [], PLATFORM)
    manifest["config"]["size"] += 1
    cache.save_manifest_cache(REF, PLATFORM, manifest, "project/image", config)

    with pytest.raises(SystemExit):
        registry.run_cli("push", "-a", "amd64", REF)

    assert "Cached image config size mismatch" in capsys.readouterr().err
    registry.authenticate.assert_not_called()
