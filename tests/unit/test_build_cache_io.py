# Tests for the portable build-cache directory. Export is bookkeeping: the entries
# this build's steps produced, the blobs they name, merged into whatever the
# directory already held. Import is the trust boundary, so most of what is below
# is a directory this program did not write trying to get a blob into the layer
# cache that is not the bytes its digest claims.

import gzip
import hashlib
import json
import os
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chroot_distro.helpers import build_cache, build_cache_io
from chroot_distro.helpers.docker import cache as docker_cache

R1 = "a" * 64
R2 = "b" * 64


@pytest.fixture
def caches(tmp_path, monkeypatch):
    layers = tmp_path / "oci_layers"
    layers.mkdir()
    index = tmp_path / "build_cache_index.json"
    monkeypatch.setattr(docker_cache, "LAYER_CACHE_DIR", str(layers))
    monkeypatch.setattr(build_cache_io, "LAYER_CACHE_DIR", str(layers))
    monkeypatch.setattr(build_cache, "_INDEX_PATH", str(index))
    monkeypatch.setattr(build_cache, "_INDEX_LOCK_PATH", str(index) + ".lock")
    return SimpleNamespace(layers=layers, index=index, shared=tmp_path / "shared")


def _layer(data=b"payload"):
    """A gzipped blob and the entry that answers for it."""
    blob = gzip.compress(data, mtime=0)
    entry = {
        "layer_digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
        "diff_id": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(blob),
        "image_config_patch": {},
    }
    return blob, entry


def _blob_name(entry):
    return entry["layer_digest"].replace(":", "_")


def _record(caches, recipe, data=b"payload"):
    """Put one built step in the local cache, blob and index entry both."""
    blob, entry = _layer(data)
    (caches.layers / _blob_name(entry)).write_bytes(blob)
    build_cache.record(recipe, entry["layer_digest"], entry["diff_id"], entry["size"])
    return blob, entry


def _plant(caches, entries, blobs):
    """Write a cache directory this program did not produce."""
    caches.shared.mkdir(parents=True, exist_ok=True)
    (caches.shared / build_cache_io.BLOBS_NAME).mkdir(exist_ok=True)
    for name, data in blobs.items():
        (caches.shared / build_cache_io.BLOBS_NAME / name).write_bytes(data)
    (caches.shared / build_cache_io.INDEX_NAME).write_text(json.dumps({"version": 1, "entries": entries}))


# ── export ────────────────────────────────────────────────────────────────────


def test_export_then_import_moves_a_step_between_machines(caches):
    blob, entry = _record(caches, R1)

    steps, size = build_cache_io.export_cache(str(caches.shared), [R1])
    assert (steps, size) == (1, len(blob))
    assert (caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)).read_bytes() == blob

    # A second machine: the index and the layer cache both empty again.
    caches.index.unlink()
    (caches.layers / _blob_name(entry)).unlink()

    assert build_cache_io.import_cache(str(caches.shared)) == (1, 0)
    recorded = build_cache.lookup(R1)
    assert recorded is not None and {key: recorded[key] for key in entry} == entry
    assert (caches.layers / _blob_name(entry)).read_bytes() == blob


def test_export_carries_only_the_recipes_it_was_given(caches):
    _record(caches, R1)
    _record(caches, R2, data=b"other")

    assert build_cache_io.export_cache(str(caches.shared), [R1])[0] == 1
    exported = json.loads((caches.shared / build_cache_io.INDEX_NAME).read_text())
    assert list(exported["entries"]) == [R1]


def test_export_drops_an_entry_whose_blob_has_been_collected(caches):
    _, entry = _record(caches, R1)
    (caches.layers / _blob_name(entry)).unlink()

    assert build_cache_io.export_cache(str(caches.shared), [R1]) == (0, 0)
    assert json.loads((caches.shared / build_cache_io.INDEX_NAME).read_text())["entries"] == {}


def test_export_accumulates_across_builds(caches):
    _record(caches, R1)
    build_cache_io.export_cache(str(caches.shared), [R1])
    _record(caches, R2, data=b"second")
    build_cache_io.export_cache(str(caches.shared), [R2])

    assert sorted(json.loads((caches.shared / build_cache_io.INDEX_NAME).read_text())["entries"]) == [R1, R2]


def test_export_leaves_a_blob_it_already_wrote_alone(caches):
    _, entry = _record(caches, R1)
    build_cache_io.export_cache(str(caches.shared), [R1])
    written = caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)
    before = written.stat().st_mtime_ns

    build_cache_io.export_cache(str(caches.shared), [R1])

    assert written.stat().st_mtime_ns == before


def test_export_replaces_a_blob_of_the_wrong_size(caches):
    blob, entry = _record(caches, R1)
    caches.shared.mkdir(parents=True)
    (caches.shared / build_cache_io.BLOBS_NAME).mkdir()
    (caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)).write_bytes(b"truncated")

    build_cache_io.export_cache(str(caches.shared), [R1])

    assert (caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)).read_bytes() == blob


def test_export_writes_an_artifact_a_later_step_can_read(caches):
    # The build that writes it is root; whoever archives the directory is not.
    _, entry = _record(caches, R1)
    build_cache_io.export_cache(str(caches.shared), [R1])

    index = caches.shared / build_cache_io.INDEX_NAME
    blob = caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)
    assert stat.S_IMODE(index.stat().st_mode) == 0o644
    assert stat.S_IMODE(blob.stat().st_mode) == 0o644


# ── a directory that is not one yet ───────────────────────────────────────────
#
# The first build in a fresh checkout is the case a shared cache directory exists
# for, so nothing there is nothing to do rather than a failure.


def test_import_of_a_directory_that_is_not_there_adds_nothing(caches):
    assert build_cache_io.import_cache(str(caches.shared)) == (0, 0)


def test_import_of_a_directory_holding_no_index_adds_nothing(caches):
    caches.shared.mkdir(parents=True)
    assert build_cache_io.import_cache(str(caches.shared)) == (0, 0)


# ── a directory that is there and is not one ──────────────────────────────────
#
# An export merges into what it finds, so a document this cannot read is one it
# must not write over: both directions refuse rather than guess.


@pytest.mark.parametrize(
    "document",
    [
        "not json{{",
        json.dumps(["entries"]),
        json.dumps({"version": 1}),
        json.dumps({"version": 1, "entries": ["h"]}),
        json.dumps({"version": 2, "entries": {}}),
        json.dumps({"entries": {}}),
    ],
)
def test_a_document_that_is_not_an_index_is_refused_both_ways(caches, document):
    caches.shared.mkdir(parents=True)
    (caches.shared / build_cache_io.INDEX_NAME).write_text(document)
    _record(caches, R1)

    with pytest.raises(ValueError):
        build_cache_io.import_cache(str(caches.shared))
    with pytest.raises(ValueError):
        build_cache_io.export_cache(str(caches.shared), [R1])
    assert (caches.shared / build_cache_io.INDEX_NAME).read_text() == document


def test_a_planted_symlink_over_the_index_is_not_read(caches):
    outside = caches.shared.parent / "outside.json"
    _, entry = _layer()
    outside.write_text(json.dumps({"version": 1, "entries": {R1: entry}}))
    caches.shared.mkdir(parents=True)
    (caches.shared / build_cache_io.INDEX_NAME).symlink_to(outside)

    with pytest.raises(ValueError):
        build_cache_io.import_cache(str(caches.shared))


def test_an_index_over_the_cap_is_refused_not_truncated(caches, monkeypatch):
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", 4096)
    caches.shared.mkdir(parents=True)
    (caches.shared / build_cache_io.INDEX_NAME).write_bytes(b"[" * 8192)

    with pytest.raises(ValueError):
        build_cache_io.import_cache(str(caches.shared))


def test_an_index_without_its_blob_directory_refuses_every_entry(caches):
    _, entry = _layer()
    caches.shared.mkdir(parents=True)
    (caches.shared / build_cache_io.INDEX_NAME).write_text(json.dumps({"version": 1, "entries": {R1: entry}}))

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)
    assert build_cache.lookup(R1) is None


# ── one entry at a time ───────────────────────────────────────────────────────
#
# Every field of an entry is read straight back out: the digest becomes a
# filename under the layer cache, and the size and the diff_id go into the
# manifest a later build publishes. So a blob lands only when its own bytes
# answer for both digests, and an entry that fails costs its step a rebuild.


def test_a_blob_that_is_not_its_digest_never_reaches_the_layer_cache(caches):
    _, entry = _layer()
    _plant(caches, {R1: entry}, {_blob_name(entry): gzip.compress(b"somebody else's", mtime=0)})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)
    assert build_cache.lookup(R1) is None
    assert os.listdir(caches.layers) == []


def test_a_blob_whose_diff_id_is_not_its_own_is_refused(caches):
    blob, entry = _layer()
    entry = {**entry, "diff_id": "sha256:" + "9f" * 32}
    _plant(caches, {R1: entry}, {_blob_name(entry): blob})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)
    assert os.listdir(caches.layers) == []


def test_a_blob_that_is_not_gzip_is_refused_rather_than_raising(caches):
    entry = {
        "layer_digest": "sha256:" + hashlib.sha256(b"raw").hexdigest(),
        "diff_id": "sha256:" + hashlib.sha256(b"raw").hexdigest(),
        "size": 3,
        "image_config_patch": {},
    }
    _plant(caches, {R1: entry}, {_blob_name(entry): b"raw"})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)


def test_a_blob_of_another_size_than_the_entry_claims_is_refused(caches):
    blob, entry = _layer()
    _plant(caches, {R1: {**entry, "size": entry["size"] + 1}}, {_blob_name(entry): blob})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)


def test_a_planted_symlink_in_the_blob_directory_is_not_followed(caches):
    blob, entry = _layer()
    outside = caches.shared.parent / "outside.gz"
    outside.write_bytes(blob)
    _plant(caches, {R1: entry}, {})
    (caches.shared / build_cache_io.BLOBS_NAME / _blob_name(entry)).symlink_to(outside)

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)
    assert os.listdir(caches.layers) == []


@pytest.mark.parametrize(
    "entry",
    [
        {},
        {"layer_digest": "sha256:not-hex", "diff_id": "sha256:" + "2b" * 32, "size": 1},
        {"layer_digest": "../../etc/passwd", "diff_id": "sha256:" + "2b" * 32, "size": 1},
        {"layer_digest": "sha512:" + "1a" * 64, "diff_id": "sha256:" + "2b" * 32, "size": 1},
        {"layer_digest": "sha256:" + "1a" * 32, "diff_id": "", "size": 1},
        {"layer_digest": "sha256:" + "1a" * 32, "diff_id": "sha256:" + "2b" * 32, "size": "big"},
    ],
)
def test_an_entry_that_is_not_shaped_like_one_is_refused(caches, entry):
    _plant(caches, {R1: entry}, {})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 1)
    assert os.listdir(caches.layers) == []


def test_a_key_that_is_not_a_recipe_hash_is_refused(caches):
    blob, entry = _layer()
    _plant(caches, {"../escape": entry, "": entry, "A" * 64: entry}, {_blob_name(entry): blob})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 3)


def test_an_entry_this_machine_already_has_is_not_replaced(caches):
    _, mine = _record(caches, R1)
    theirs_blob, theirs = _layer(b"a different step")
    _plant(caches, {R1: theirs}, {_blob_name(theirs): theirs_blob})

    assert build_cache_io.import_cache(str(caches.shared)) == (0, 0)
    recorded = build_cache.lookup(R1)
    assert recorded is not None and recorded["layer_digest"] == mine["layer_digest"]


def test_a_blob_already_in_the_layer_cache_is_taken_as_verified(caches):
    # The layer cache holds either the verified bytes for a digest or nothing, so
    # a name already standing there is not re-read out of a stranger's directory.
    blob, entry = _layer()
    (caches.layers / _blob_name(entry)).write_bytes(blob)
    _plant(caches, {R1: entry}, {_blob_name(entry): b"nonsense"})

    assert build_cache_io.import_cache(str(caches.shared)) == (1, 0)
    assert (caches.layers / _blob_name(entry)).read_bytes() == blob


def test_a_step_served_from_cache_is_still_a_step_the_build_exports(caches):
    # The hit path is the one that would be easy to leave out, and a matrix whose
    # steps all hit would then export an empty directory.
    from chroot_distro.arch import Platform
    from chroot_distro.helpers.build_engine import run_step

    blob, entry = _record(caches, R1)
    stage = SimpleNamespace(
        rootfs_dir=str(caches.layers),
        rootfs_fd=None,
        layers=[],
        parent_layer_digest=None,
        shell=["/bin/sh", "-c"],
        platform=Platform("linux", "arm64"),
        base_manifest_digest="sha256:m",
    )
    engine = SimpleNamespace(
        current=stage,
        no_cache=False,
        expansion_scope=dict,
        report_cache_hit=lambda instr: None,
        target_platform=Platform("linux", "arm64"),
        build_platform=Platform("linux", "amd64"),
        isolation_mode="none",
        stages={},
        step_recipes=set(),
    )
    instr = {"name": "RUN", "flags": {}, "value": "echo", "exec_form": False, "heredocs": [], "lineno": 1}
    hit = {"layer_digest": entry["layer_digest"], "size": entry["size"], "diff_id": entry["diff_id"]}

    with patch.object(run_step, "cache_lookup", return_value=hit), patch.object(run_step, "apply_layer"):
        run_step.do_run(engine, instr)

    recipe = next(iter(engine.step_recipes))
    build_cache.record(recipe, entry["layer_digest"], entry["diff_id"], entry["size"])
    assert build_cache_io.export_cache(str(caches.shared), engine.step_recipes) == (1, len(blob))
