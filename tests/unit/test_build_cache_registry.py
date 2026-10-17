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
