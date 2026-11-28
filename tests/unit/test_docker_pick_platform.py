import pytest

from chroot_distro.arch import Platform
from chroot_distro.helpers.docker.pull import _layer_short_id, _matches_platform


@pytest.mark.parametrize(("architecture", "variant", "compatible"), [
    ("arm64", "v8", True),
    ("arm64", "v9", False),
    ("amd64", "v1", True),
    ("amd64", "v2", False),
])
def test_platform_variant_matches_only_the_supported_default(architecture, variant, compatible):
    fields = {"os": "linux", "architecture": architecture, "variant": variant}
    assert _matches_platform(fields, Platform("linux", architecture)) is compatible


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
