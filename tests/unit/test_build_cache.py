import json

from chroot_distro.helpers import build_cache


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
    build_cache.record("h1", "sha256:layer", "sha256:diff", 42, {"Env": ["A=1"]})
    entry = build_cache.lookup("h1")
    assert entry is not None
    assert entry["layer_digest"] == "sha256:layer"
    assert entry["diff_id"] == "sha256:diff"
    assert entry["size"] == 42
    assert entry["image_config_patch"] == {"Env": ["A=1"]}
    assert entry["created"].endswith("Z")


def test_record_defaults_empty_patch(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    build_cache.record("h2", "d", "i", 0)
    assert build_cache.lookup("h2")["image_config_patch"] == {}


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
