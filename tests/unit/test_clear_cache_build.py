# Tests for `clear-cache --build-cache`: the build index goes, and with it the
# layer blobs nothing else names. The parts that matter are what it refuses to
# do -- delete a blob a cached image still lists, delete anything while a
# reference source cannot be read, delete anything while another command is
# mid-build -- and that it works on an index too corrupt to parse, which is one
# of the reasons to reach for the flag.

import json
import os
from types import SimpleNamespace

import pytest

from chroot_distro import locking
from chroot_distro.commands.clear_cache import command_clear_cache
from chroot_distro.helpers import build_cache
from chroot_distro.helpers.docker import cache as docker_cache

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32


@pytest.fixture
def cache_dirs(tmp_path, monkeypatch):
    layers = tmp_path / "oci_layers"
    manifests = tmp_path / "oci_manifests"
    layers.mkdir()
    manifests.mkdir()
    index = tmp_path / "build_cache_index.json"

    monkeypatch.setattr(docker_cache, "LAYER_CACHE_DIR", str(layers))
    monkeypatch.setattr(docker_cache, "MANIFEST_CACHE_DIR", str(manifests))
    monkeypatch.setattr("chroot_distro.commands.clear_cache.LAYER_CACHE_DIR", str(layers))
    monkeypatch.setattr(build_cache, "_INDEX_PATH", str(index))
    monkeypatch.setattr(build_cache, "_INDEX_LOCK_PATH", str(index) + ".lock")
    monkeypatch.setattr(locking, "LOCKS_DIR", str(tmp_path / "locks"))
    monkeypatch.setattr(locking, "_BUILD_LOCKS_DIR", str(tmp_path / "locks" / "build"))
    return SimpleNamespace(layers=layers, manifests=manifests, index=index)


def _blob(cache_dirs, digest, data=b"layer"):
    path = cache_dirs.layers / digest.replace(":", "_")
    path.write_bytes(data)
    return path


def _manifest(cache_dirs, name, digests):
    payload = {"manifest": {"layers": [{"digest": d} for d in digests]}, "repo": "library/x"}
    (cache_dirs.manifests / name).write_text(json.dumps(payload))


def _args(verbose=False):
    return SimpleNamespace(build_cache=True, verbose=verbose, quiet=False)


def test_the_index_and_the_layers_only_it_pinned_are_dropped(cache_dirs, capsys):
    blob = _blob(cache_dirs, DIGEST)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)

    command_clear_cache(_args())

    assert not cache_dirs.index.exists()
    assert not blob.exists()
    err = capsys.readouterr().err
    assert "build cache index" in err
    assert "Reclaimed" in err


def test_a_layer_a_cached_image_lists_is_kept(cache_dirs):
    kept = _blob(cache_dirs, DIGEST)
    stranded = _blob(cache_dirs, OTHER)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)
    build_cache.record("h2", OTHER, "sha256:diff2", 5)
    _manifest(cache_dirs, "img.json", [DIGEST])

    command_clear_cache(_args())

    assert not cache_dirs.index.exists()
    assert kept.exists()
    assert not stranded.exists()


def test_the_manifest_cache_is_left_alone(cache_dirs):
    _manifest(cache_dirs, "img.json", [DIGEST])
    _blob(cache_dirs, DIGEST)

    command_clear_cache(_args())

    assert os.listdir(cache_dirs.manifests) == ["img.json"]


def test_an_index_too_corrupt_to_parse_is_still_dropped(cache_dirs):
    # The flag unlinks the index and never reads it, which is the point: a
    # delete set derived from its entries would fail exactly here.
    cache_dirs.index.write_text("{ not json either")
    blob = _blob(cache_dirs, DIGEST)

    command_clear_cache(_args())

    assert not cache_dirs.index.exists()
    assert not blob.exists()


def test_an_unreadable_manifest_entry_stops_everything(cache_dirs, capsys):
    blob = _blob(cache_dirs, DIGEST)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)
    (cache_dirs.manifests / "broken.json").write_text("{ this is not json")

    with pytest.raises(SystemExit) as exc:
        command_clear_cache(_args())

    assert exc.value.code == 1
    # The keep set is computed before anything is deleted.
    assert cache_dirs.index.exists()
    assert blob.exists()
    assert "broken.json" in capsys.readouterr().err


def test_an_in_flight_manifest_write_is_not_an_unreadable_entry(cache_dirs):
    # atomic_write's temporary is half a file by definition; reading it would
    # abort a sweep that has no reason to fail.
    _manifest(cache_dirs, "img.json", [DIGEST])
    (cache_dirs.manifests / "img.json.abc123.tmp").write_text("{ half written")
    kept = _blob(cache_dirs, DIGEST)

    command_clear_cache(_args())

    assert kept.exists()


def test_it_refuses_while_another_command_holds_an_exclusive_lock(cache_dirs, capsys):
    blob = _blob(cache_dirs, DIGEST)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)

    with locking.ContainerLock("ubuntu", exclusive=True, command="build"):
        with pytest.raises(SystemExit) as exc:
            command_clear_cache(_args())

    assert exc.value.code == 1
    assert cache_dirs.index.exists()
    assert blob.exists()
    assert "is running" in capsys.readouterr().err


def test_a_shared_holder_does_not_block_the_sweep(cache_dirs):
    # A login session or a backup holds a shared lock and writes nothing to the
    # cache, so the probe must not see it.
    blob = _blob(cache_dirs, DIGEST)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)

    with locking.ContainerLock("ubuntu", exclusive=False, command="login"):
        command_clear_cache(_args())

    assert not cache_dirs.index.exists()
    assert not blob.exists()


def test_a_failure_to_remove_the_index_leaves_every_blob_alone(cache_dirs, monkeypatch, capsys):
    # Unpinned-then-kept is untidy; pinned-then-deleted is the direction that
    # matters, so the index goes first and its failure ends the command.
    blob = _blob(cache_dirs, DIGEST)
    build_cache.record("h1", DIGEST, "sha256:diff", 5)
    monkeypatch.setattr(
        "chroot_distro.commands.clear_cache.discard_index",
        lambda: (_ for _ in ()).throw(OSError(13, "Permission denied")),
    )

    with pytest.raises(SystemExit) as exc:
        command_clear_cache(_args())

    assert exc.value.code == 1
    assert blob.exists()
    assert "Permission denied" in capsys.readouterr().err


def test_an_empty_build_cache_says_so(cache_dirs, capsys):
    command_clear_cache(_args())

    assert "build cache is already empty" in capsys.readouterr().err.lower()


def test_nothing_collectable_still_reports_the_index(cache_dirs, capsys):
    build_cache.record("h1", DIGEST, "sha256:diff", 5)
    _blob(cache_dirs, DIGEST)
    _manifest(cache_dirs, "img.json", [DIGEST])

    command_clear_cache(_args())

    err = capsys.readouterr().err
    assert "unreferenced layer" not in err
    assert "Reclaimed" in err


def test_verbose_names_the_index_and_each_blob(cache_dirs, capsys):
    build_cache.record("h1", DIGEST, "sha256:diff", 5)
    _blob(cache_dirs, DIGEST)

    command_clear_cache(_args(verbose=True))

    err = capsys.readouterr().err
    assert "build_cache_index.json" in err
    assert DIGEST.replace(":", "_") in err
