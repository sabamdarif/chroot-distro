# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Verify registry metadata through pull_image with a temporary manifest cache."""

import hashlib
import io
import json
import os
import urllib.error
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro.arch import Platform
from chroot_distro.helpers import download
from chroot_distro.helpers.docker import cache, pull
from chroot_distro.helpers.docker.media import OCI_INDEX_MEDIA, OCI_MANIFEST_MEDIA

BASE = "https://registry.example"
REF = "registry.example/project/image:latest"
API = BASE + "/v2/project/image"
TAG = API + "/manifests/latest"
PLATFORM = Platform("linux", "amd64")
LAYER_DIGEST = "sha256:" + "a" * 64
CONFIG = b'{ "os": "linux", "architecture": "amd64", "config": null }\n'


def _descriptor(body):
    return {"digest": "sha256:" + hashlib.sha256(body).hexdigest(), "size": len(body)}


def _manifest(config, layers=None):
    if layers is None:
        layers = [{"digest": LAYER_DIGEST}]
    return json.dumps({"schemaVersion": 2, "config": config, "layers": layers}, indent=2).encode()


def _index(child):
    platform = {"os": "linux", "architecture": "amd64"}
    return json.dumps({"manifests": [{**child, "platform": platform}]}).encode()


def _response(body, content_type="", *, length=None):
    response = io.BytesIO(body)
    response.headers = {"Content-Type": content_type, "Content-Length": str(len(body) if length is None else length)}
    return response


@pytest.fixture
def registry(tmp_path, monkeypatch):
    root = tmp_path / "rootfs"
    root.mkdir()
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    monkeypatch.setattr(cache, "MANIFEST_CACHE_DIR", str(manifest_dir))
    monkeypatch.setattr(cache, "LAYER_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(pull, "get_auth_token", Mock(return_value=("Bearer fixture", BASE)))

    routes = {}
    requests = []

    def open_response(req):
        assert req.get_header("Authorization") == "Bearer fixture"
        requests.append(req.full_url)
        result = routes[req.full_url].pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(pull, "opener", lambda insecure: SimpleNamespace(open=open_response))
    download_layers = Mock()
    apply_layer = Mock()
    monkeypatch.setattr(pull, "_download_layers_parallel", download_layers)
    monkeypatch.setattr(pull, "apply_layer", apply_layer)

    def pull_image():
        root_fd = os.open(root, os.O_RDONLY)
        try:
            return pull.pull_image(REF, root_fd, PLATFORM)
        finally:
            os.close(root_fd)

    return SimpleNamespace(
        routes=routes, requests=requests, pull=pull_image, manifest_dir=manifest_dir,
        download_layers=download_layers, apply_layer=apply_layer,
    )


def _failed_pull(registry, error):
    with pytest.raises(RuntimeError, match=error):
        registry.pull()
    assert not list(registry.manifest_dir.iterdir())
    registry.download_layers.assert_not_called()
    registry.apply_layer.assert_not_called()


@pytest.mark.parametrize("indexed", [False, True])
def test_verified_image_caches_exact_metadata_and_can_be_reused_offline(registry, indexed):
    config = _descriptor(CONFIG)
    manifest = _manifest(config)
    child = _descriptor(manifest)
    manifest_url = TAG
    if indexed:
        registry.routes[TAG] = [_response(_index(child), OCI_INDEX_MEDIA)]
        manifest_url = API + "/manifests/" + child["digest"]
    registry.routes[manifest_url] = [_response(manifest, OCI_MANIFEST_MEDIA + "; charset=utf-8")]
    config_url = API + "/blobs/" + config["digest"]
    registry.routes[config_url] = [_response(CONFIG)]

    result = registry.pull()

    assert result["image_config"] == json.loads(CONFIG)
    assert result["manifest"]["_digest"] == child["digest"]
    assert result["manifest"]["_ct"] == OCI_MANIFEST_MEDIA
    assert registry.requests == ([TAG] if indexed else []) + [manifest_url, config_url]
    assert registry.apply_layer.call_count == 1

    with open(cache.layer_cache_path(LAYER_DIGEST), "wb") as layer:
        layer.write(b"cached layer")
    registry.requests.clear()
    assert registry.pull() == result
    assert registry.requests == []


@pytest.mark.parametrize("target", ["Child manifest", "Image config"])
@pytest.mark.parametrize(
    "problem,error",
    [("size", "size mismatch"), ("digest", "digest mismatch"), ("object", "must be a JSON object")],
)
def test_rejects_unverified_metadata(registry, target, problem, error):
    config = _descriptor(CONFIG)
    manifest = _manifest(config)
    body = manifest if target == "Child manifest" else CONFIG
    if problem == "object":
        body = b"[]"
    descriptor = _descriptor(body)
    if problem == "size":
        descriptor["size"] += 1
    elif problem == "digest":
        descriptor["digest"] = "sha256:" + "b" * 64

    if target == "Child manifest":
        registry.routes[TAG] = [_response(_index(descriptor), OCI_INDEX_MEDIA)]
        url = API + "/manifests/" + descriptor["digest"]
        registry.routes[url] = [_response(body, OCI_MANIFEST_MEDIA)]
    else:
        registry.routes[TAG] = [_response(_manifest(descriptor), OCI_MANIFEST_MEDIA)]
        url = API + "/blobs/" + descriptor["digest"]
        registry.routes[url] = [_response(body)]

    _failed_pull(registry, f"{target} {error}")
    assert registry.requests == [TAG, url]


@pytest.mark.parametrize("target", ["Child manifest", "Image config"])
@pytest.mark.parametrize(
    "fields,error",
    [
        ({}, "SHA-256 digest"),
        ({"size": 20, "digest": "sha256:abcd"}, "SHA-256 digest"),
        ({"digest": LAYER_DIGEST}, "invalid size"),
        ({"digest": LAYER_DIGEST, "size": True}, "invalid size"),
        ({"digest": LAYER_DIGEST, "size": -1}, "invalid size"),
        ({"digest": LAYER_DIGEST, "size": pull.MAX_METADATA_BYTES + 1}, "invalid size"),
    ],
)
def test_invalid_metadata_descriptor_is_rejected_before_request(registry, target, fields, error):
    if target == "Child manifest":
        registry.routes[TAG] = [_response(_index(fields), OCI_INDEX_MEDIA)]
    else:
        registry.routes[TAG] = [_response(_manifest(fields), OCI_MANIFEST_MEDIA)]
    _failed_pull(registry, f"{target} descriptor .*{error}")
    assert registry.requests == [TAG]


@pytest.mark.parametrize(
    "body,error",
    [
        (b"[]", "must be a JSON object"),
        (b"\xff", "not valid JSON"),
        (b'{"mediaType": []}', "mediaType must be a string"),
        (b'{"manifests": {}}', "'manifests' must be a list"),
        (b'{"manifests": [null]}', "entries must be objects"),
        (b'{"manifests": [{"platform": {"variant": []}}]}', "platform must be an object with string fields"),
        (b'{"layers": "wrong"}', "'layers' must be a list"),
        (b'{"layers": [null]}', "Layer descriptor must be an object"),
    ],
)
def test_rejects_malformed_manifest_fields_before_publication(registry, body, error):
    registry.routes[TAG] = [_response(body)]
    _failed_pull(registry, error)
    assert registry.requests == [TAG]


@pytest.mark.parametrize(
    "layer,error",
    [
        ({"digest": "sha256:abcd"}, "lowercase SHA-256 digest"),
        ({"digest": "sha512:" + "a" * 128}, "lowercase SHA-256 digest"),
        ({"digest": LAYER_DIGEST + "\n"}, "lowercase SHA-256 digest"),
        ({"digest": LAYER_DIGEST, "size": False}, "invalid size"),
        ({"digest": LAYER_DIGEST, "size": 2**63}, "invalid size"),
    ],
)
def test_rejects_invalid_fresh_layer_descriptors(registry, layer, error):
    registry.routes[TAG] = [_response(_manifest(_descriptor(CONFIG), [layer]))]
    _failed_pull(registry, f"Layer descriptor .*{error}")
    assert registry.requests == [TAG]


@pytest.mark.parametrize(("body", "error"), [(b'{"architecture": []}', "architecture"), (b'{"config": []}', "'config'")])
def test_rejects_invalid_config_fields(registry, body, error):
    config = _descriptor(body)
    registry.routes[TAG] = [_response(_manifest(config))]
    registry.routes[API + "/blobs/" + config["digest"]] = [_response(body)]
    _failed_pull(registry, f"Image config .*{error}")


def test_rejects_unavailable_config_without_caching(registry):
    config = _descriptor(CONFIG)
    registry.routes[TAG] = [_response(_manifest(config))]
    url = API + "/blobs/" + config["digest"]
    registry.routes[url] = [urllib.error.HTTPError(url, 404, "Not Found", {}, None)]
    _failed_pull(registry, "Could not fetch image config.*HTTP Error 404")
    assert registry.requests == [TAG, url]


def test_retries_truncated_config_before_checking_descriptor(registry, monkeypatch):
    monkeypatch.setattr(download.time, "sleep", Mock())
    config = _descriptor(CONFIG)
    registry.routes[TAG] = [_response(_manifest(config))]
    url = API + "/blobs/" + config["digest"]
    registry.routes[url] = [_response(CONFIG[:-1], length=len(CONFIG)), _response(CONFIG)]
    assert registry.pull()["image_config"] == json.loads(CONFIG)
    assert registry.requests == [TAG, url, url]
