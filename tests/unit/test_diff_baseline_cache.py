"""Tests for the diff image-baseline cache."""

import json
from unittest.mock import patch

from chroot_distro.helpers import layer_diff


def test_cache_miss_builds_and_writes(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    fake_baseline = {"usr/bin/foo": ("file", 10), "etc": ("dir",)}
    digests = ["sha256:a", "sha256:b"]

    with patch.object(layer_diff, "baseline_from_layers", return_value=fake_baseline) as m:
        result = layer_diff.cached_baseline_from_layers(["/l/a", "/l/b"], digests, str(cache))

    m.assert_called_once()
    assert result == fake_baseline
    on_disk = json.loads(cache.read_text())
    assert on_disk["digests"] == digests
    assert on_disk["version"] == layer_diff._BASELINE_CACHE_VERSION


def test_cache_hit_skips_rebuild(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    digests = ["sha256:a"]
    cache.write_text(
        json.dumps(
            {
                "version": layer_diff._BASELINE_CACHE_VERSION,
                "digests": digests,
                "baseline": {"usr/bin/foo": ["file", 10], "etc": ["dir"]},
            }
        )
    )

    with patch.object(layer_diff, "baseline_from_layers") as m:
        result = layer_diff.cached_baseline_from_layers(["/l/a"], digests, str(cache))

    m.assert_not_called()
    # Tuples restored from JSON lists
    assert result == {"usr/bin/foo": ("file", 10), "etc": ("dir",)}


def test_cache_digest_mismatch_rebuilds(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    cache.write_text(
        json.dumps(
            {
                "version": layer_diff._BASELINE_CACHE_VERSION,
                "digests": ["sha256:old"],
                "baseline": {"a": ["file", 1]},
            }
        )
    )
    rebuilt = {"b": ("file", 2)}

    with patch.object(layer_diff, "baseline_from_layers", return_value=rebuilt) as m:
        result = layer_diff.cached_baseline_from_layers(["/l/new"], ["sha256:new"], str(cache))

    m.assert_called_once()
    assert result == rebuilt
    assert json.loads(cache.read_text())["digests"] == ["sha256:new"]


def test_corrupt_cache_falls_back(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    cache.write_text("{ not json")
    rebuilt = {"x": ("file", 3)}

    with patch.object(layer_diff, "baseline_from_layers", return_value=rebuilt) as m:
        result = layer_diff.cached_baseline_from_layers(["/l/x"], ["sha256:x"], str(cache))

    m.assert_called_once()
    assert result == rebuilt


def test_baseline_cache_is_valid_true_after_clear_cache(tmp_path):
    """A matching cache is valid even when the raw layer tars are gone.

    This is the 'diff after clear-cache' path: the layer blobs under the
    shared cache dir may be wiped, but the baseline recorded next to the
    container survives and is enough to diff.
    """
    cache = tmp_path / "diff_baseline.json"
    digests = ["sha256:a", "sha256:b"]
    cache.write_text(
        json.dumps(
            {
                "version": layer_diff._BASELINE_CACHE_VERSION,
                "digests": digests,
                "baseline": {"usr/bin/foo": ["file", 10]},
            }
        )
    )
    assert layer_diff.baseline_cache_is_valid(str(cache), digests) is True


def test_baseline_cache_is_valid_false_on_mismatch(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    cache.write_text(
        json.dumps(
            {
                "version": layer_diff._BASELINE_CACHE_VERSION,
                "digests": ["sha256:old"],
                "baseline": {"a": ["file", 1]},
            }
        )
    )
    assert layer_diff.baseline_cache_is_valid(str(cache), ["sha256:new"]) is False


def test_baseline_cache_is_valid_false_when_missing(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    assert layer_diff.baseline_cache_is_valid(str(cache), ["sha256:a"]) is False


def test_baseline_cache_is_valid_false_on_corrupt(tmp_path):
    cache = tmp_path / "diff_baseline.json"
    cache.write_text("{ not json")
    assert layer_diff.baseline_cache_is_valid(str(cache), ["sha256:a"]) is False
