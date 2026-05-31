from unittest.mock import patch

import pytest

from chroot_distro.exceptions import (
    ChrootDistroError,
    ContainerNotFoundError,
    InvalidNameError,
)
from chroot_distro.paths import (
    container_dir,
    container_from_spec,
    container_locks_for_spec_pair,
    container_manifest,
    container_rootfs,
    resolve_container_path,
)


def test_paths():
    assert container_dir("debian").endswith("containers/debian")
    assert container_rootfs("debian").endswith("containers/debian/rootfs")
    assert container_manifest("debian").endswith("containers/debian/manifest.json")


def test_container_from_spec():
    assert container_from_spec("alpine:/etc/hosts") == "alpine"
    assert container_from_spec("/etc/hosts") is None


def test_resolve_container_path_host():
    path = resolve_container_path("/tmp/foo")
    assert path == "/tmp/foo"


def test_resolve_container_path_container(tmp_path):
    # Setup test container rootfs
    containers_dir = tmp_path / "containers"
    rootfs_dir = containers_dir / "mycont" / "rootfs"
    rootfs_dir.mkdir(parents=True)

    with patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)):
        # Valid path
        res = resolve_container_path("mycont:/etc/hosts")
        assert res == str(rootfs_dir / "etc/hosts")

        # Invalid name spec
        with pytest.raises(InvalidNameError):
            resolve_container_path("-invalid:/etc/hosts")

        # Nonexistent container
        with pytest.raises(ContainerNotFoundError):
            resolve_container_path("nonexistent:/etc/hosts")

        # Escapes rootfs
        with pytest.raises(ChrootDistroError) as exc_info:
            resolve_container_path("mycont:../../etc/hosts")
        assert "escapes the container directory" in str(exc_info.value)


def test_container_locks_for_spec_pair():
    locks = container_locks_for_spec_pair("alpine:/src", "debian:/dst", "copy")
    assert len(locks) == 2
    # Sorted by name
    assert locks[0]._display == "alpine"
    assert locks[0]._exclusive is False
    assert locks[1]._display == "debian"
    assert locks[1]._exclusive is True

    locks = container_locks_for_spec_pair("alpine:/src", "alpine:/dst", "copy")
    assert len(locks) == 1
    assert locks[0]._display == "alpine"
    assert locks[0]._exclusive is True

    locks = container_locks_for_spec_pair("/src", "alpine:/dst", "copy")
    assert len(locks) == 1
    assert locks[0]._display == "alpine"
    assert locks[0]._exclusive is True

    locks = container_locks_for_spec_pair("alpine:/src", "/dst", "copy")
    assert len(locks) == 1
    assert locks[0]._display == "alpine"
    assert locks[0]._exclusive is False

    locks = container_locks_for_spec_pair("/src", "/dst", "copy")
    assert len(locks) == 0
