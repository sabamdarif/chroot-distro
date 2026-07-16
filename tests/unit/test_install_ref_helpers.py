import pytest

from chroot_distro.commands import install


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("/abs/path.tar", True),
        ("./rel.tar", True),
        ("../up.tar", True),
        ("~/home.tar", True),
        ("ubuntu:22.04", False),
        ("http://x/y.tar", False),
    ],
)
def test_is_local_path(ref, expected):
    assert install._is_local_path(ref) is expected


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("http://x/y", True),
        ("https://x/y", True),
        ("ftp://x/y", False),
        ("/local", False),
    ],
)
def test_is_url(ref, expected):
    assert install._is_url(ref) is expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/tmp/Ubuntu-22.04.tar.gz", "ubuntu-22.04"),
        ("archlinux.tar.xz", "archlinux"),
        ("my_image.oci.tar", "my_image"),
        ("Weird Name!.tgz", "weird-name"),
        ("--leading.tar", "leading"),
        ("a___b.tar", "a___b"),
    ],
)
def test_derive_local_name(path, expected):
    assert install._derive_local_name(path) == expected
