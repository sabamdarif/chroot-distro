# The registry cache backend's on-disk shape, with no network: a staged cache
# directory packs into one blob and unpacks back into a directory import_cache
# reads, and an unpack refuses a member that climbs out of the directory.

import os
import tarfile

from chroot_distro.helpers import build_cache_io
from chroot_distro.helpers import build_cache_registry as reg


def _stage(tmp_path):
    stage = tmp_path / "stage"
    blobs = stage / build_cache_io.BLOBS_NAME
    blobs.mkdir(parents=True)
    (stage / build_cache_io.INDEX_NAME).write_text('{"version": 1, "entries": {}}')
    (blobs / "abc123").write_bytes(b"blob-bytes")
    return stage


def test_pack_then_unpack_round_trips_the_document(tmp_path):
    stage = _stage(tmp_path)
    blob = reg._pack_directory(str(stage))
    out = tmp_path / "out"
    out.mkdir()
    reg._unpack_directory(blob, str(out))
    assert (out / build_cache_io.INDEX_NAME).read_text() == '{"version": 1, "entries": {}}'
    assert (out / build_cache_io.BLOBS_NAME / "abc123").read_bytes() == b"blob-bytes"


def test_unpack_drops_members_outside_the_document(tmp_path):
    blob = tmp_path / "evil.tar.gz"
    with tarfile.open(blob, "w:gz") as tf:
        for name in ("../escape", "/absolute", "blobs/../../escape2", "other.txt"):
            info = tarfile.TarInfo(name)
            data = b"x"
            info.size = len(data)
            import io

            tf.addfile(info, io.BytesIO(data))
        # The legitimate members, to prove the filter keeps them.
        idx = tarfile.TarInfo(build_cache_io.INDEX_NAME)
        payload = b'{"version": 1, "entries": {}}'
        idx.size = len(payload)
        import io

        tf.addfile(idx, io.BytesIO(payload))
    out = tmp_path / "out"
    out.mkdir()
    reg._unpack_directory(str(blob), str(out))
    assert (out / build_cache_io.INDEX_NAME).exists()
    assert not (tmp_path / "escape").exists()
    assert not (out / "other.txt").exists()
    assert not (out / "escape2").exists()


def test_invalid_registry_refs_are_rejected_before_auth_or_export(monkeypatch):
    import pytest

    from chroot_distro.helpers.docker.refs import InvalidReferenceError

    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid reference reached registry or local cache")

    monkeypatch.setattr(reg, "get_auth_token", unexpected)
    monkeypatch.setattr(build_cache_io, "export_cache", unexpected)
    for reference in ("cache?scope=other", "cache@sha256:" + "0" * 64):
        with pytest.raises(InvalidReferenceError):
            reg.pull_cache(reference)
        with pytest.raises(InvalidReferenceError):
            reg.push_cache(reference, [])


def test_registry_cache_keeps_hub_verified_for_pull_and_push(monkeypatch):
    from unittest.mock import Mock

    from chroot_distro.helpers.docker.transport import REGISTRY_URL

    auth = Mock(return_value=("", REGISTRY_URL))
    fetch = Mock(return_value={"layers": [{"digest": "sha256:fixture"}]})
    download = Mock(return_value="fixture")
    exists = Mock(return_value=False)
    upload = Mock()
    put = Mock()
    monkeypatch.setattr(reg, "get_auth_token", auth)
    monkeypatch.setattr(reg, "_get_manifest", fetch)
    monkeypatch.setattr(reg, "download_blob", download)
    monkeypatch.setattr(reg, "_blob_exists", exists)
    monkeypatch.setattr(reg, "_upload_blob_bytes", upload)
    monkeypatch.setattr(reg, "_put_manifest", put)
    monkeypatch.setattr(reg, "_unpack_directory", Mock())
    monkeypatch.setattr(build_cache_io, "import_cache", Mock(return_value=(0, 0)))
    monkeypatch.setattr(build_cache_io, "export_cache", Mock(return_value=(0, 0)))

    for ref in ("cache", "Registry-1.Docker.IO:443/library/cache"):
        reg.pull_cache(ref, insecure=True)
        reg.push_cache(ref, [], insecure=True)
        assert fetch.call_args.args[1] == put.call_args.args[1] == "latest"
    for mock in (auth, fetch, download, exists, upload, put):
        assert mock.call_args_list
        assert all(call.kwargs["insecure"] is False for call in mock.call_args_list)
