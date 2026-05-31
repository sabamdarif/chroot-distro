from chroot_distro.helpers.docker.refs import derive_alias, parse_image_ref


def test_parse_image_ref():
    # Docker Hub images
    assert parse_image_ref("ubuntu") == ("", "library/ubuntu", "latest")
    assert parse_image_ref("ubuntu:24.04") == ("", "library/ubuntu", "24.04")
    assert parse_image_ref("myuser/img:1.0") == ("", "myuser/img", "1.0")
    assert parse_image_ref("docker.io/library/ubuntu:24.04") == ("", "library/ubuntu", "24.04")
    assert parse_image_ref("index.docker.io/library/ubuntu:latest") == ("", "library/ubuntu", "latest")

    # Custom registry images
    assert parse_image_ref("ghcr.io/foo/bar:latest") == ("ghcr.io", "foo/bar", "latest")
    assert parse_image_ref("localhost:5000/foo:tag") == ("localhost:5000", "foo", "tag")

def test_derive_alias():
    assert derive_alias("ubuntu:24.04") == "ubuntu"
    assert derive_alias("myuser/img:tag") == "img"
    assert derive_alias("ghcr.io/foo/bar:tag") == "bar"
    assert derive_alias("localhost:5000/foo:tag") == "foo"
