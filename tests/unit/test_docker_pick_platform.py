import pytest

from chroot_distro.helpers.docker.pull import _layer_short_id, _pick_platform


def _entry(arch, variant="", os_="linux", digest="sha256:x"):
    plat = {"architecture": arch, "os": os_}
    if variant:
        plat["variant"] = variant
    return {"platform": plat, "digest": digest}


def test_pick_platform_exact_arch_variant():
    entries = [_entry("arm", "v7", digest="sha256:a"), _entry("arm64", digest="sha256:b")]
    assert _pick_platform(entries, "arm", "v7", "img")["digest"] == "sha256:a"


def test_pick_platform_arch_match_ignores_windows():
    entries = [_entry("amd64", os_="windows", digest="sha256:w"), _entry("amd64", digest="sha256:l")]
    assert _pick_platform(entries, "amd64", "", "img")["digest"] == "sha256:l"


def test_pick_platform_variant_agnostic_fallback():
    # No entry has the requested variant, but arch matches -> fallback picks it.
    entries = [_entry("arm64", "v8", digest="sha256:a")]
    assert _pick_platform(entries, "arm64", "v9", "img")["digest"] == "sha256:a"


def test_pick_platform_empty_variant_entry_matches_requested_variant():
    entries = [_entry("arm64", digest="sha256:a")]
    assert _pick_platform(entries, "arm64", "v8", "img")["digest"] == "sha256:a"


def test_pick_platform_no_match_raises_with_available():
    entries = [_entry("arm", "v7"), _entry("ppc64le")]
    with pytest.raises(RuntimeError, match="arm/v7.*ppc64le|ppc64le.*arm/v7"):
        _pick_platform(entries, "amd64", "", "img")


def test_pick_platform_no_linux_entries_reports_none():
    entries = [_entry("amd64", os_="windows")]
    with pytest.raises(RuntimeError, match="none"):
        _pick_platform(entries, "amd64", "", "img")


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        ("sha256:abcdef0123456789", "abcdef012345"),
        ("abcdef0123456789", "abcdef012345"),
        ("sha256:short", "short"),
    ],
)
def test_layer_short_id(digest, expected):
    assert _layer_short_id(digest) == expected
