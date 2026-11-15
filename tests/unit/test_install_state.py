"""Install state stays tied to the descriptors that were opened for it."""

import errno
import os
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import dirfd, locking, paths
from chroot_distro.commands import install, list_cmd, login
from chroot_distro.commands import run as run_mod


@pytest.fixture
def store(tmp_path, monkeypatch):
    containers = tmp_path / "data" / "chroot-distro" / "containers"
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(containers))
    monkeypatch.setattr(paths, "IS_TERMUX", False)
    monkeypatch.setattr(list_cmd, "CONTAINERS_DIR", str(containers))
    monkeypatch.setattr(locking, "RUNTIME_DIR", str(containers.parent))
    monkeypatch.setattr(install, "BASE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(install, "IS_TERMUX", False)
    monkeypatch.setattr(install, "pull_image", Mock(return_value=None))
    monkeypatch.setattr(install, "_print_start_hints", Mock())
    return containers


def run_install():
    install._run_install("box", "alpine", None, None, "x86_64")


def marked_tree(store):
    rootfs = store / "box" / "rootfs"
    rootfs.mkdir(parents=True)
    (rootfs.parent / ".install-incomplete").touch()
    return rootfs


@pytest.mark.parametrize("platform,part", [("linux", "runtime"), ("linux", "store"), ("linux", "container"), ("termux", "var"), ("termux", "runtime"), ("termux", "store"), ("termux", "container")])
def test_install_refuses_symlinked_storage(tmp_path, monkeypatch, store, platform, part):
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    runtime = anchor / "chroot-distro"
    if platform == "termux":
        runtime = anchor / "var" / "lib" / "chroot-distro"
    containers = runtime / "containers"
    monkeypatch.setattr(paths, "IS_TERMUX", platform == "termux")
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(containers))
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "keep"
    victim.write_text("KEEP")
    target = {"var": anchor / "var", "runtime": runtime, "store": containers, "container": containers / "box"}[part]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SystemExit) as exc:
        run_install()
    assert exc.value.code == 1
    assert list(outside.iterdir()) == [victim]
    assert victim.read_text() == "KEEP"
    install.pull_image.assert_not_called()


def test_platform_anchor_alias_is_allowed(tmp_path, monkeypatch, store):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(paths, "IS_TERMUX", True)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(alias))
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(alias / "var/lib/chroot-distro/containers"))
    run_install()
    assert (actual / "var/lib/chroot-distro/containers/box/rootfs").is_dir()


def test_termux_fixups_receive_the_pinned_rootfs(store, monkeypatch):
    seen = []
    monkeypatch.setattr(install, "IS_TERMUX", True)

    def fixup(path, *, root_fd):
        assert os.path.samestat(os.stat(path), os.fstat(root_fd))
        seen.append(root_fd)

    monkeypatch.setattr(install, "register_android_ids", fixup)
    monkeypatch.setattr(install, "configure_android_rootfs", fixup)
    run_install()
    assert len(seen) == 2
    assert seen[0] == seen[1]


@pytest.mark.parametrize("part", ["container", "store", "rootfs"])
@pytest.mark.parametrize("failure", [False, True])
def test_replaced_storage_is_preserved(store, monkeypatch, part, failure):
    saved = store.parent / "saved"
    original = store / "box"
    replacement = None

    def pull(ref, fd, *args, **kwargs):
        nonlocal replacement
        payload, _ = dirfd.open_new_at(fd, "payload")
        os.close(payload)
        source = {"container": original, "store": store, "rootfs": original / "rootfs"}[part]
        source.rename(saved)
        source.mkdir()
        replacement = source / "keep"
        replacement.write_text("KEEP")
        if failure:
            raise RuntimeError("injected failure")
        return {"image_ref": "alpine", "manifest": {}, "image_config": {}}

    monkeypatch.setattr(install, "pull_image", pull)
    with pytest.raises(SystemExit):
        run_install()
    assert replacement.read_text() == "KEEP"
    assert list(replacement.parent.iterdir()) == [replacement]
    container = {"container": saved, "store": saved / "box", "rootfs": original}[part]
    assert (container / ".install-incomplete").is_file()
    if not failure:
        assert (container / "manifest.json").is_file()


def test_retry_clears_pinned_rootfs_and_stale_metadata(store, monkeypatch, tmp_path):
    rootfs = marked_tree(store)
    (rootfs / "old").write_text("old")
    (rootfs.parent / "manifest.json").write_text('{"image_ref":"old"}')
    original_inode = rootfs.stat().st_ino
    archive = tmp_path / "plain.tar"
    archive.touch()

    def extract(path, fd, arch):
        assert os.fstat(fd).st_ino == original_inode
        assert os.listdir(fd) == []
        assert (rootfs.parent / ".install-incomplete").is_file()
        assert not (rootfs.parent / "manifest.json").exists()
        output, _ = dirfd.open_new_at(fd, "new")
        os.close(output)
        return None

    monkeypatch.setattr(install, "install_from_local_file", extract)
    install._run_install("box", str(archive), str(archive), None, "x86_64")
    assert rootfs.stat().st_ino == original_inode
    assert (rootfs / "new").exists()
    assert not (rootfs.parent / ".install-incomplete").exists()
    assert not (rootfs.parent / "manifest.json").exists()


@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink", "fifo", "directory"])
def test_marker_types_block_execution_and_agree_with_list(store, tmp_path, monkeypatch, kind):
    rootfs = store / "box" / "rootfs"
    rootfs.mkdir(parents=True)
    marker = rootfs.parent / ".install-incomplete"
    outside = tmp_path / "outside"
    outside.write_text("KEEP")
    if kind == "regular":
        marker.touch()
    elif kind == "symlink":
        marker.symlink_to(tmp_path / "missing")
    elif kind == "hardlink":
        os.link(outside, marker)
    elif kind == "fifo":
        os.mkfifo(marker)
    else:
        marker.mkdir()
    assert paths.is_install_incomplete("box")
    assert not paths.container_is_installed("box")
    assert paths.installed_containers() == []
    assert list_cmd._iter_container_names() == ([], ["box"])
    metadata = Mock(side_effect=AssertionError("metadata reached"))
    setup = Mock(side_effect=AssertionError("setup reached"))
    monkeypatch.setattr(run_mod, "_read_image_config", metadata)
    monkeypatch.setattr(login, "_detect_dist_type", setup)
    with pytest.raises(SystemExit):
        run_mod.command_run(SimpleNamespace(container_name="box"))
    with pytest.raises(SystemExit):
        login.command_login(SimpleNamespace(container_name="box"))
    metadata.assert_not_called()
    setup.assert_not_called()
    assert outside.read_text() == "KEEP"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_retry_replaces_marker_without_touching_its_target(store, tmp_path, kind):
    rootfs = marked_tree(store)
    marker = rootfs.parent / ".install-incomplete"
    marker.unlink()
    outside = tmp_path / "outside"
    outside.write_text("KEEP")
    outside.chmod(0o600)
    if kind == "symlink":
        marker.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, marker)
    else:
        os.mkfifo(marker)
    run_install()
    assert outside.read_text() == "KEEP"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    assert not marker.exists()


def test_run_lock_spans_metadata_and_login(store, monkeypatch):
    (store / "box" / "rootfs").mkdir(parents=True)
    calls = []

    def check_lock():
        competitor = locking.ContainerLock("box", exclusive=True)
        assert not competitor.acquire()

    def metadata(name):
        check_lock()
        calls.append("metadata")
        return {"Cmd": ["/bin/sh"]}

    def handoff(args):
        check_lock()
        with locking.ContainerLock("box", exclusive=False):
            check_lock()
        calls.append("login")

    monkeypatch.setattr(run_mod, "_read_image_config", metadata)
    monkeypatch.setattr(run_mod, "command_login", handoff)
    run_mod.command_run(SimpleNamespace(container_name="box"))
    assert calls == ["metadata", "login"]
    with locking.ContainerLock("box", exclusive=True):
        pass


@pytest.mark.parametrize("point", ["marker_file", "marker_directory", "parent_directory", "final_unlink", "final_directory", "restoration"])
def test_install_state_io_failures_are_visible(store, monkeypatch, capsys, point):
    real_fsync = os.fsync
    real_unlink = os.unlink
    injected = False

    def fsync(fd):
        nonlocal injected
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        names = os.listdir(fd) if is_dir else []
        rootfs = store / "box" / "rootfs"
        creation = point == "marker_file" and not is_dir
        creation |= point == "marker_directory" and ".install-incomplete" in names and "rootfs" not in names
        creation |= point == "parent_directory" and is_dir and not rootfs.exists() and not (store / "box" / ".install-incomplete").exists()
        final = point in ("final_directory", "restoration") and is_dir and "rootfs" in names and ".install-incomplete" not in names
        restoring = point == "restoration" and injected and is_dir and "rootfs" in names
        if (creation or final) and not injected or restoring:
            injected = True
            raise OSError(errno.EIO, "injected fsync failure")
        return real_fsync(fd)

    def unlink(path, *args, **kwargs):
        nonlocal injected
        if point == "final_unlink" and path == ".install-incomplete" and not injected:
            injected = True
            raise PermissionError("injected unlink failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "unlink", unlink)
    with pytest.raises(SystemExit) as exc:
        run_install()
    assert exc.value.code == 1
    assert injected
    assert not paths.container_is_installed("box")
    err = capsys.readouterr().err
    assert "Finished installation" not in err
    assert "Failed to install" in err
    if point.startswith("marker") or point == "parent_directory":
        install.pull_image.assert_not_called()
    else:
        assert (store / "box" / ".install-incomplete").exists()
    if point == "restoration":
        assert "Could not restore" in err


def test_retry_marker_is_continuous_and_synced_before_clearing(store, monkeypatch):
    rootfs = marked_tree(store)
    (rootfs / "old").touch()
    synced = False
    real_fsync = os.fsync
    real_remove = dirfd.rmtree_at

    def fsync(fd):
        nonlocal synced
        if os.path.samestat(os.fstat(fd), rootfs.parent.stat()):
            assert (rootfs.parent / ".install-incomplete").is_file()
            synced = True
        return real_fsync(fd)

    def remove(fd, name, **kwargs):
        assert synced
        assert (rootfs.parent / ".install-incomplete").is_file()
        return real_remove(fd, name, **kwargs)

    def pull(*args, **kwargs):
        monkeypatch.setattr(os, "fsync", real_fsync)
        return None

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(dirfd, "rmtree_at", remove)
    monkeypatch.setattr(install, "pull_image", pull)
    run_install()


def test_retry_clears_original_rootfs_after_its_name_is_replaced(store, monkeypatch):
    rootfs = marked_tree(store)
    (rootfs / "old").touch()
    moved = rootfs.parent / "original-rootfs"
    real_listdir = dirfd.listdir_at
    original = rootfs.stat()
    swapped = False

    def listdir(fd):
        nonlocal swapped
        if not swapped and os.path.samestat(os.fstat(fd), original):
            swapped = True
            rootfs.rename(moved)
            rootfs.mkdir()
            (rootfs / "keep").write_text("KEEP")
        return real_listdir(fd)

    monkeypatch.setattr(dirfd, "listdir_at", listdir)
    with pytest.raises(SystemExit):
        run_install()
    assert not (moved / "old").exists()
    assert (rootfs / "keep").read_text() == "KEEP"
    assert (rootfs.parent / ".install-incomplete").exists()


def test_retry_deep_restrictive_tree(store):
    rootfs = marked_tree(store)
    fd = dirfd.opendir(str(rootfs))
    try:
        for _ in range(1100):
            os.mkdir("d", dir_fd=fd)
            child = dirfd.opendir_at(fd, "d")
            os.fchmod(fd, 0o500)
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    run_install()
    assert list(rootfs.iterdir()) == []


def test_directory_marker_refuses_retry_without_clearing_payload(store):
    rootfs = marked_tree(store)
    marker = rootfs.parent / ".install-incomplete"
    marker.unlink()
    marker.mkdir()
    (rootfs / "keep").write_text("KEEP")
    with pytest.raises(SystemExit):
        run_install()
    assert (rootfs / "keep").read_text() == "KEEP"
    install.pull_image.assert_not_called()


def test_interrupt_closes_descriptors_and_retains_marker(store, monkeypatch):
    seen = []
    real_open = install.open_container_dir

    def open_container(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        seen.append(fd)
        return fd

    def interrupt(ref, fd, *args, **kwargs):
        seen.append(fd)
        raise KeyboardInterrupt

    def hard_exit(code):
        assert code == 1
        for fd in seen:
            with pytest.raises(OSError):
                os.fstat(fd)
        assert (store / "box" / ".install-incomplete").is_file()
        raise SystemExit(code)

    monkeypatch.setattr(install, "open_container_dir", open_container)
    monkeypatch.setattr(install, "pull_image", interrupt)
    monkeypatch.setattr(os, "_exit", hard_exit)
    with pytest.raises(SystemExit):
        run_install()


@pytest.mark.parametrize("destination", [".install-incomplete", "manifest.json"])
def test_install_rejects_substituted_atomic_publication(store, monkeypatch, tmp_path, destination):
    outside = tmp_path / "outside"
    outside.write_text("KEEP")
    outside.chmod(0o600)
    real_replace = os.replace

    def replace(src, dst, **kwargs):
        if dst == destination:
            os.unlink(src, dir_fd=kwargs["src_dir_fd"])
            os.symlink(outside, src, dir_fd=kwargs["src_dir_fd"])
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    install.pull_image.return_value = {"image_ref": "alpine", "manifest": {}, "image_config": {}}
    with pytest.raises(SystemExit):
        run_install()
    assert not paths.container_is_installed("box")
    assert outside.read_text() == "KEEP"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    if destination == ".install-incomplete":
        install.pull_image.assert_not_called()
        assert not (store / "box" / "rootfs").exists()
    else:
        assert (store / "box" / ".install-incomplete").is_file()


def test_dns_writes_follow_retained_rootfs_after_container_replacement(store, monkeypatch):
    original = store.parent / "original"
    replacement = store / "box" / "rootfs" / "etc"

    def pull(ref, fd, *args, **kwargs):
        os.mkdir("etc", dir_fd=fd)
        (store / "box").rename(original)
        replacement.mkdir(parents=True)
        (replacement / "hosts").write_text("KEEP HOSTS")
        (replacement / "resolv.conf").write_text("KEEP DNS")
        return None

    monkeypatch.setattr(install, "pull_image", pull)
    monkeypatch.setattr("chroot_distro.helpers.rootfs.host_nameservers", lambda: ["192.0.2.1"])
    with pytest.raises(SystemExit):
        run_install()
    assert (replacement / "hosts").read_text() == "KEEP HOSTS"
    assert (replacement / "resolv.conf").read_text() == "KEEP DNS"
    assert "127.0.0.1" in (original / "rootfs/etc/hosts").read_text()
    assert (original / "rootfs/etc/resolv.conf").read_text() == "nameserver 192.0.2.1\n"


def test_parent_links_and_marker_are_synced_before_rootfs_creation(store, monkeypatch):
    real_fsync = os.fsync
    real_mkdir = os.mkdir
    synced = set()

    def fsync(fd):
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            synced.add((st.st_dev, st.st_ino))
        return real_fsync(fd)

    def mkdir(name, *args, **kwargs):
        if name == "rootfs":
            assert (store / "box" / ".install-incomplete").is_file()
            for parent in [store.parent.parent, store.parent, store, store / "box"]:
                st = parent.stat()
                assert (st.st_dev, st.st_ino) in synced
        return real_mkdir(name, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "mkdir", mkdir)
    run_install()


def test_failed_install_can_be_removed(store, monkeypatch):
    from chroot_distro.commands import remove

    rootfs = marked_tree(store)
    (rootfs / "partial").touch()
    monkeypatch.setattr(remove, "RUNTIME_DIR", str(store.parent))
    monkeypatch.setattr(remove.session, "get_active_chroot_pids", lambda _: [])
    monkeypatch.setattr(remove.session, "reset", Mock())
    monkeypatch.setattr(remove.session, "clear_mount_options", Mock())
    monkeypatch.setattr(remove.namespace, "get_live_holder", lambda _: None)
    monkeypatch.setattr(remove.mount_manager, "unmount_all", Mock())
    monkeypatch.setattr(remove.mount_manager, "get_active_mounts", lambda _: [])
    remove.command_remove(SimpleNamespace(container_name="box"))
    assert not rootfs.parent.exists()


def test_local_archive_install_and_conflict_preserve_content(store, tmp_path):
    import io
    import tarfile

    archive = tmp_path / "rootfs.tar.gz"
    content = b"guest data"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("payload")
        member.size = len(content)
        member.uid = os.getuid()
        member.gid = os.getgid()
        output.addfile(member, io.BytesIO(content))
    install._run_install("box", str(archive), str(archive), None, "x86_64")
    assert paths.container_is_installed("box")
    assert (store / "box/rootfs/payload").read_bytes() == content
    with pytest.raises(SystemExit):
        run_install()
    assert (store / "box/rootfs/payload").read_bytes() == content
    assert not (store / "box/.install-incomplete").exists()


def test_marker_without_rootfs_is_listed_and_retryable(store, monkeypatch):
    container = store / "box"
    container.mkdir(parents=True)
    (container / ".install-incomplete").touch()
    assert list_cmd._iter_container_names() == ([], ["box"])
    run_install()
    assert paths.container_is_installed("box")
    assert list_cmd._iter_container_names() == (["box"], [])


def test_unusable_storage_does_not_hide_other_containers(store, tmp_path):
    (store / "safe" / "rootfs").mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / "rootfs").mkdir(parents=True)
    (store / "box").symlink_to(outside, target_is_directory=True)
    (store / "invalid\nname" / "rootfs").mkdir(parents=True)
    assert paths.installed_containers() == ["safe"]
    assert list_cmd._iter_container_names() == (["safe"], [])
    assert list(outside.iterdir()) == [outside / "rootfs"]
