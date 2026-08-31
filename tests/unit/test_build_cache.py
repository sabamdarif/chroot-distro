import errno
import json
import os
import subprocess
import sys

import pytest

from chroot_distro import atomic
from chroot_distro.helpers import build_cache

# An entry names a layer to apply and the diff_id that goes into the published
# manifest, and lookup() hands back only an entry whose fields are shaped like
# ones, so a test recording a step has to record digests.
LAYER = "sha256:" + "1a" * 32
DIFF = "sha256:" + "2b" * 32


def _redirect(monkeypatch, tmp_path):
    index = tmp_path / "build_cache_index.json"
    monkeypatch.setattr(build_cache, "_INDEX_PATH", str(index))
    monkeypatch.setattr(build_cache, "_INDEX_LOCK_PATH", str(index) + ".lock")
    return index


def test_lookup_none_and_missing(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    assert build_cache.lookup(None) is None
    assert build_cache.lookup("") is None
    assert build_cache.lookup("deadbeef") is None


def test_record_then_lookup_roundtrip(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    build_cache.record("h1", LAYER, DIFF, 42, {"Env": ["A=1"]})
    entry = build_cache.lookup("h1")
    assert entry is not None
    assert entry["layer_digest"] == LAYER
    assert entry["diff_id"] == DIFF
    assert entry["size"] == 42
    assert entry["image_config_patch"] == {"Env": ["A=1"]}
    assert entry["created"].endswith("Z")


def test_record_defaults_empty_patch(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    build_cache.record("h2", LAYER, DIFF, 0)
    assert build_cache.lookup("h2")["image_config_patch"] == {}


# ── an entry that is not shaped like one ──────────────────────────────────────
#
# Every field below is read straight back out: the layer digest becomes a
# filename under the layer cache, and the size and diff_id go into the manifest
# the build publishes. A miss costs a rebuild; believing one of these costs a
# traceback out of `build`, or a stranger's file packed as this step's layer.


@pytest.mark.parametrize(
    "entry",
    [
        {},
        {"layer_digest": LAYER},
        {"layer_digest": "sha256:not-hex", "diff_id": DIFF, "size": 1},
        {"layer_digest": "../../etc/passwd", "diff_id": DIFF, "size": 1},
        {"layer_digest": LAYER, "diff_id": "", "size": 1},
        {"layer_digest": LAYER, "diff_id": DIFF, "size": "big"},
        {"layer_digest": LAYER, "diff_id": DIFF, "size": True},
        {"layer_digest": LAYER, "diff_id": DIFF, "size": -1},
        {"layer_digest": LAYER, "diff_id": DIFF, "size": 1, "image_config_patch": ["Env"]},
    ],
)
def test_a_malformed_entry_is_a_miss(monkeypatch, tmp_path, entry):
    index = _redirect(monkeypatch, tmp_path)
    index.write_text(json.dumps({"version": 1, "entries": {"h": entry}}))

    assert build_cache.lookup("h") is None


def test_an_entry_without_a_patch_is_still_usable(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    index.write_text(json.dumps({"version": 1, "entries": {"h": {"layer_digest": LAYER, "diff_id": DIFF, "size": 0}}}))

    assert build_cache.lookup("h") is not None


def test_load_index_recovers_from_corrupt(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    index.write_text("not json{{")
    data = build_cache._load_index()
    assert data == {"version": 1, "entries": {}}


def test_load_index_normalises_bad_shapes(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    index.write_text(json.dumps({"entries": ["oops"]}))
    data = build_cache._load_index()
    assert data["entries"] == {}
    assert data["version"] == 1


def test_compute_recipe_hash_is_stable_and_sensitive(monkeypatch, tmp_path):
    instr = {"name": "RUN", "flags": {"mount": "cache"}, "value": "make", "heredocs": []}
    h1 = build_cache.compute_recipe_hash("sha256:parent", instr, "extra")
    h2 = build_cache.compute_recipe_hash("sha256:parent", instr, "extra")
    assert h1 == h2
    assert h1 != build_cache.compute_recipe_hash("sha256:other", instr, "extra")
    assert h1 != build_cache.compute_recipe_hash("sha256:parent", instr, b"different")


def test_compute_recipe_hash_folds_heredocs_and_flags(monkeypatch, tmp_path):
    base = {"name": "RUN", "value": "x"}
    with_hd = {"name": "RUN", "value": "x", "heredocs": [{"body": "line\n"}]}
    assert build_cache.compute_recipe_hash(None, base) != build_cache.compute_recipe_hash(None, with_hd)

    no_flags = {"name": "ENV", "value": "A=1"}
    with_flags = {"name": "ENV", "value": "A=1", "flags": {"k": "v"}}
    assert build_cache.compute_recipe_hash(None, no_flags) != build_cache.compute_recipe_hash(None, with_flags)


def test_canonical_value_lists_are_json(monkeypatch, tmp_path):
    assert build_cache._canonical_value(["a", "b"]) == '["a","b"]'
    assert build_cache._canonical_value("plain") == "plain"


def test_canonical_flags_handles_list_values():
    flags = {"mount": ["type=cache,target=/a", "type=tmpfs,target=/b"], "network": "host"}
    canon = build_cache._canonical_flags(flags)
    assert canon == 'mount=["type=cache,target=/a","type=tmpfs,target=/b"]&network=host'


def test_recipe_hash_perturbed_by_mount_flag():
    plain = {"name": "RUN", "value": "pip install x"}
    with_mount = {
        "name": "RUN",
        "value": "pip install x",
        "flags": {"mount": "type=cache,target=/root/.cache"},
    }
    other_mount = {
        "name": "RUN",
        "value": "pip install x",
        "flags": {"mount": "type=cache,target=/other"},
    }
    h_plain = build_cache.compute_recipe_hash(None, plain)
    h_mount = build_cache.compute_recipe_hash(None, with_mount)
    h_other = build_cache.compute_recipe_hash(None, other_mount)
    assert len({h_plain, h_mount, h_other}) == 3


# ── planted entries ───────────────────────────────────────────────────────────
#
# The index and its lock live in the download cache, which on Termux sits under
# the $PREFIX bound read-write into every non-isolated container. Both names are
# fixed, so a guest can leave something of its own standing under either one.
# The index is read, so what matters there is that a plant is never followed and
# never believed; the lock is created, so what matters there is that a plant is
# replaced -- and that a plant which cannot be replaced still leaves the build
# able to record its step.


def test_a_planted_symlink_over_the_index_is_not_read(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"version": 1, "entries": {"h": {"layer_digest": LAYER, "diff_id": DIFF, "size": 1}}}))
    index.symlink_to(outside)

    assert build_cache.lookup("h") is None


def test_a_planted_fifo_over_the_index_does_not_stall_the_build(tmp_path):
    # O_NOFOLLOW says nothing about a FIFO, and opening one for reading waits
    # for a writer a hostile guest never supplies.
    index = tmp_path / "build_cache_index.json"
    os.mkfifo(str(index))

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys;"
            "sys.path.insert(0, 'src');"
            "from chroot_distro.helpers import build_cache;"
            f"build_cache._INDEX_PATH = {str(index)!r};"
            "print(build_cache.lookup('h'))",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.stdout.strip() == "None", completed.stderr


def test_a_planted_symlink_over_the_lock_is_replaced(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("KEEP")
    lock = tmp_path / (index.name + ".lock")
    lock.symlink_to(outside)

    build_cache.record("h", LAYER, DIFF, 1)

    assert build_cache.lookup("h") is not None
    assert not lock.is_symlink()
    assert outside.read_text() == "KEEP"


def test_a_lock_name_that_cannot_be_cleared_still_records_the_step(monkeypatch, tmp_path):
    # Unlike a container lock, an unserialised record() risks a concurrent
    # build's entry and nothing else, so it goes ahead without the flock.
    index = _redirect(monkeypatch, tmp_path)
    planted = tmp_path / (index.name + ".lock")
    planted.mkdir()
    (planted / "occupied").write_text("x")

    build_cache.record("h", LAYER, DIFF, 1)

    assert build_cache.lookup("h") is not None
    assert (planted / "occupied").exists()


def test_discard_index_drops_a_planted_symlink_without_following_it(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    index.symlink_to(outside)

    removed, size = build_cache.discard_index()

    assert removed is True
    assert size == len(str(outside))
    assert not index.exists() and not index.is_symlink()
    assert outside.read_text() == "{}"


# ── the walk down to the cache directory ──────────────────────────────────────
#
# On Termux the cache is nested inside RUNTIME_DIR, so `cache` is a component of
# the walk rather than its root and a guest can plant that too. Off Termux it is
# a root of its own and there is nothing below it to walk.


def _nested(monkeypatch, tmp_path):
    """The Termux geometry: the cache nested inside RUNTIME_DIR.

    `atomic` decides what to walk from its own copy of the two roots, so the
    write side has to be pointed at the same tree as the read side for the
    nesting to be under test at all.
    """
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(build_cache, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(atomic, "_STATE_ROOTS", (str(runtime),))
    index = runtime / "cache" / "build_cache_index.json"
    monkeypatch.setattr(build_cache, "_INDEX_PATH", str(index))
    monkeypatch.setattr(build_cache, "_INDEX_LOCK_PATH", str(index) + ".lock")
    return index


def test_a_nested_cache_directory_is_created_and_used(monkeypatch, tmp_path):
    index = _nested(monkeypatch, tmp_path)

    build_cache.record("h", LAYER, DIFF, 1)

    assert index.is_file()
    assert build_cache.lookup("h") is not None
    assert build_cache.discard_index()[0] is True


def test_a_symlinked_cache_directory_is_refused_not_followed(monkeypatch, tmp_path):
    index = _nested(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(index.parent))

    with pytest.raises(OSError):
        build_cache.record("h", LAYER, DIFF, 1)

    assert os.listdir(str(outside)) == []
    assert build_cache.lookup("h") is None
    # Not (False, 0): `clear-cache --build-cache` reads that as "no index, carry
    # on and collect the layers", and a directory it cannot walk is not proof
    # that nothing is pinned. The refusal has to reach the caller.
    with pytest.raises(OSError):
        build_cache.discard_index()


# How much of the index this program will read is its own choice, for the same
# reason: json.loads on whatever the read returned stops only at end of file, so
# without a ceiling whoever can write under that fixed name decides how many
# bytes a build holds in memory before finding out the document is nonsense.


def test_an_index_over_the_cap_is_refused_not_truncated(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", 4096)
    index.write_bytes(b"[" * 4097)

    with pytest.raises(OSError) as exc:
        build_cache._read_index()
    assert exc.value.errno == errno.EFBIG


def test_an_index_at_the_cap_still_reads(monkeypatch, tmp_path):
    index = _redirect(monkeypatch, tmp_path)
    payload = json.dumps({"version": 1, "entries": {"h": {"layer_digest": LAYER, "diff_id": DIFF, "size": 0}}}).encode()
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", len(payload))
    index.write_bytes(payload)

    assert build_cache.lookup("h") == {"layer_digest": LAYER, "diff_id": DIFF, "size": 0}


def test_a_padded_index_is_refused_by_size_alone(monkeypatch, tmp_path):
    # The document parses: whitespace after a JSON value is legal, so nothing
    # but the cap stands between this file and its bytes being resident.
    index = _redirect(monkeypatch, tmp_path)
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", 4096)
    index.write_bytes(json.dumps({"version": 1, "entries": {"h": {}}}).encode() + b" " * 8192)

    assert build_cache.lookup("h") is None


def test_the_cap_counts_bytes_read_not_the_size_reported(monkeypatch, tmp_path):
    # A size check would pass for a file being appended to as it is read. The
    # cap is on the read itself, so a descriptor that keeps yielding raises.
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", 4096)
    monkeypatch.setattr(build_cache, "_READ_CHUNK", 512)
    r, w = os.pipe()
    try:
        os.write(w, b"x" * 4608)
        os.close(w)
        w = -1
        with pytest.raises(OSError) as exc:
            build_cache._read_capped(r)
    finally:
        os.close(r)
        if w != -1:
            os.close(w)
    assert exc.value.errno == errno.EFBIG


def test_recording_over_an_oversized_index_replaces_it(monkeypatch, tmp_path):
    # Whatever holds that many bytes is not an index this program wrote, so the
    # step being recorded goes into a fresh one rather than failing the build.
    index = _redirect(monkeypatch, tmp_path)
    monkeypatch.setattr(build_cache, "_MAX_INDEX_BYTES", 4096)
    index.write_bytes(b"[" * 8192)

    build_cache.record("h", LAYER, DIFF, 1)

    assert build_cache.lookup("h")["layer_digest"] == LAYER
    assert index.stat().st_size < 4096
