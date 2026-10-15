# The build cache's bound: `record()` stamps `last_used`, `touch()` re-stamps
# the recipes a build used once at the end (not one write per lookup), and
# `prune()` evicts least-recently-used first until the pinned size is under the
# cap.

import json

from chroot_distro.helpers import build_cache

LAYER = "sha256:" + "1a" * 32
DIFF = "sha256:" + "2b" * 32


def _redirect(monkeypatch, tmp_path):
    index = tmp_path / "build_cache_index.json"
    monkeypatch.setattr(build_cache, "_INDEX_PATH", str(index))
    monkeypatch.setattr(build_cache, "_INDEX_LOCK_PATH", str(index) + ".lock")
    return index


def _record(monkeypatch, tmp_path, recipe, size, last_used=None):
    """Write one entry directly, controlling last_used."""
    _redirect(monkeypatch, tmp_path)
    index = tmp_path / "build_cache_index.json"
    data = {"version": 1, "entries": {}}
    if index.exists():
        data = json.loads(index.read_text())
    data["entries"][recipe] = {
        "layer_digest": LAYER,
        "diff_id": DIFF,
        "size": size,
        "image_config_patch": {},
        "created": "2026-01-01T00:00:00Z",
        "last_used": last_used,
    }
    index.write_text(json.dumps(data))


def test_record_stamps_last_used(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    build_cache.record("h1", LAYER, DIFF, 10)
    entry = build_cache.lookup("h1")
    assert isinstance(entry["last_used"], float)


def test_touch_re_stamps_only_named_recipes(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "old", 10, last_used=1.0)
    _record(monkeypatch, tmp_path, "used", 10, last_used=2.0)
    build_cache.touch(["used"])
    data = json.loads((tmp_path / "build_cache_index.json").read_text())
    assert data["entries"]["old"]["last_used"] == 1.0
    assert data["entries"]["used"]["last_used"] > 2.0


def test_touch_ignores_unknown_recipes(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "old", 10, last_used=1.0)
    build_cache.touch(["ghost"])
    data = json.loads((tmp_path / "build_cache_index.json").read_text())
    assert "ghost" not in data["entries"]


def test_prune_evicts_least_recently_used_first(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "oldest", 100, last_used=1.0)
    _record(monkeypatch, tmp_path, "middle", 100, last_used=2.0)
    _record(monkeypatch, tmp_path, "newest", 100, last_used=3.0)
    dropped, reclaimed = build_cache.prune(150)
    assert dropped == 2
    assert reclaimed == 200
    data = json.loads((tmp_path / "build_cache_index.json").read_text())
    assert list(data["entries"]) == ["newest"]


def test_prune_stops_at_the_cap(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "a", 100, last_used=1.0)
    _record(monkeypatch, tmp_path, "b", 100, last_used=2.0)
    dropped, _ = build_cache.prune(200)
    assert dropped == 0
    data = json.loads((tmp_path / "build_cache_index.json").read_text())
    assert len(data["entries"]) == 2


def test_prune_zero_cap_is_no_cap(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "a", 100, last_used=1.0)
    assert build_cache.prune(0) == (0, 0)


def test_prune_treats_a_missing_stamp_as_oldest(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "nostamp", 100, last_used=None)
    _record(monkeypatch, tmp_path, "new", 100, last_used=9.0)
    dropped, _ = build_cache.prune(100)
    assert dropped == 1
    data = json.loads((tmp_path / "build_cache_index.json").read_text())
    assert list(data["entries"]) == ["new"]


def test_touch_is_one_index_write_for_a_whole_build(monkeypatch, tmp_path):
    _record(monkeypatch, tmp_path, "a", 10, last_used=1.0)
    _record(monkeypatch, tmp_path, "b", 10, last_used=1.0)
    writes = []
    orig_save = build_cache._save_index
    monkeypatch.setattr(build_cache, "_save_index", lambda d: (writes.append(len(d["entries"])), orig_save(d)))
    build_cache.touch(["a", "b"])
    assert writes == [2]
