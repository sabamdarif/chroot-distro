import os
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
    container_log_path,
    container_manifest,
    container_rootfs,
    pin_path,
    refuse_src_dest_overlap,
    resolve_container_child,
    resolve_container_path,
)


def test_paths():
    assert container_dir("debian").endswith("containers/debian")
    assert container_rootfs("debian").endswith("containers/debian/rootfs")
    assert container_manifest("debian").endswith("containers/debian/manifest.json")


def test_container_log_path(tmp_path):
    with patch("chroot_distro.paths.RUNTIME_DIR", str(tmp_path)):
        log_path = container_log_path("debian")
    assert log_path.endswith("data/debian/run.log")
    # The parent data dir is created on demand.
    assert (tmp_path / "data" / "debian").is_dir()


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


def test_installed_containers_permission_denied(monkeypatch):
    import errno

    def _deny_listdir(*_args, **_kwargs):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("os.listdir", _deny_listdir)

    with patch("logging.Logger.warning") as mock_warn:
        from chroot_distro.paths import installed_containers
        assert installed_containers() == []
        mock_warn.assert_called_once()
        assert "Permission denied: cannot read containers directory" in mock_warn.call_args[0][0]


def test_container_from_spec_follows_the_scp_rule():
    # A colon separates a container from a path only when nothing before it is a
    # directory separator, so a host file whose name holds a colon stays reachable.
    assert container_from_spec("box:/etc") == "box"
    assert container_from_spec("a:b") == "a"
    assert container_from_spec("./a:b") is None
    assert container_from_spec("/tmp/a:b") is None
    assert container_from_spec("/etc/hosts") is None


@pytest.fixture
def rootfs(tmp_path, monkeypatch):
    containers = tmp_path / "containers"
    root = containers / "distro" / "rootfs"
    root.mkdir(parents=True)
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))
    return root


def test_a_guest_symlink_is_resolved_as_the_guest_would_see_it(rootfs):
    (rootfs / "real").mkdir()
    os.symlink("/real", rootfs / "etc")
    assert resolve_container_path("distro:/etc/hosts") == str(rootfs / "real" / "hosts")


def test_a_symlink_out_of_the_rootfs_is_re_anchored_rather_than_followed(rootfs, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), rootfs / "escape")
    # `escape -> /tmp/.../outside` is an ordinary link as seen from inside the
    # container, where it names the guest's own copy of that path.
    resolved = resolve_container_path("distro:/escape/f.txt")
    assert resolved == str(rootfs) + str(outside / "f.txt")


def test_dotdot_cannot_climb_out_of_the_rootfs(rootfs):
    (rootfs / "sub").mkdir()
    os.symlink("../../..", rootfs / "up")
    # Written in the spec itself `..` is rejected outright; reached through a
    # symlink it is clamped at the root, as it is for a process inside the chroot.
    assert resolve_container_path("distro:/up") == str(rootfs)
    assert resolve_container_path("distro:/sub/../sub") == str(rootfs / "sub")


def test_a_symlink_loop_stops_at_the_hop_limit(rootfs):
    os.symlink("b", rootfs / "a")
    os.symlink("a", rootfs / "b")
    with pytest.raises(ChrootDistroError) as exc_info:
        resolve_container_path("distro:/a")
    assert "too many symbolic links" in str(exc_info.value)


def test_deref_leaf_false_keeps_the_final_component(rootfs):
    (rootfs / "target").write_text("data")
    os.symlink("target", rootfs / "link")
    # `copy --move` renames the entry, so the link itself is what it must name;
    # a plain copy acts on what the link points at.
    assert resolve_container_path("distro:/link") == str(rootfs / "target")
    assert resolve_container_path("distro:/link", deref_leaf=False) == str(rootfs / "link")


def test_overlap_is_weighed_on_the_resolved_paths(rootfs):
    (rootfs / "data" / "inner").mkdir(parents=True)
    (rootfs / "data" / "f.txt").write_text("payload")
    os.link(rootfs / "data" / "f.txt", rootfs / "hardlink")
    os.symlink("/data", rootfs / "backup")

    def check(src, dest, **kwargs):
        refuse_src_dest_overlap(
            src, resolve_container_path(src), dest, resolve_container_path(dest), **kwargs
        )

    # A hardlinked pair is two names for one inode, which a string comparison
    # cannot see.
    with pytest.raises(ChrootDistroError, match="same file"):
        check("distro:/data/f.txt", "distro:/hardlink")
    # A planted symlink is enough to make one directory the other.
    with pytest.raises(ChrootDistroError, match="same file"):
        check("distro:/data", "distro:/backup")
    with pytest.raises(ChrootDistroError, match="into itself"):
        check("distro:/data", "distro:/data/inner")

    # A source inside the destination is only a problem when the destination's
    # extra entries are about to be pruned, so it is refused for `sync --delete`
    # alone.
    check("distro:/data/inner", "distro:/data")
    with pytest.raises(ChrootDistroError):
        check("distro:/data/inner", "distro:/data", pruning=True)


def test_resolve_container_child_walks_the_appended_name(rootfs):
    (rootfs / "opt" / "real").mkdir(parents=True)
    os.symlink("real", rootfs / "opt" / "f.txt")
    resolved = resolve_container_path("distro:/opt")

    # The base name appended to a directory destination is a container path
    # component like any other, so it gets the same walk.
    assert resolve_container_child("distro:/opt", resolved, "f.txt") == str(rootfs / "opt" / "real")
    assert resolve_container_child("distro:/opt", resolved, "f.txt", deref_leaf=False) == str(
        rootfs / "opt" / "f.txt"
    )


def test_pin_path_refuses_a_component_that_became_a_symlink(rootfs, tmp_path):
    (rootfs / "dir").mkdir()
    resolved = resolve_container_path("distro:/dir/f.txt")

    outside = tmp_path / "outside"
    outside.mkdir()
    os.rmdir(rootfs / "dir")
    os.symlink(str(outside), rootfs / "dir")

    with pytest.raises(ChrootDistroError) as exc_info:
        with pin_path("distro:/dir/f.txt", resolved):
            pass
    assert "changed while it was being resolved" in str(exc_info.value)
    assert os.listdir(outside) == []


def test_pin_path_inside_refuses_a_root_that_became_a_symlink(rootfs, tmp_path):
    (rootfs / "root").mkdir()
    resolved = resolve_container_path("distro:/root")
    os.rmdir(rootfs / "root")
    os.symlink(str(tmp_path), rootfs / "root")

    # Without inside=True only the parent is pinned, so a root everything is
    # written *underneath* has to be walked too or the whole subtree follows it.
    with pytest.raises(ChrootDistroError):
        with pin_path("distro:/root", resolved, inside=True):
            pass


def test_pin_path_creates_missing_directories_along_the_walk(rootfs):
    resolved = resolve_container_path("distro:/a/b/f.txt")
    with pin_path("distro:/a/b/f.txt", resolved, create=True) as pinned:
        assert pinned.leaf == "f.txt"
        os.close(os.open("f.txt", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=pinned.dir_fd))
    assert (rootfs / "a" / "b" / "f.txt").is_file()
