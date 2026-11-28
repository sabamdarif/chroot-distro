"""Removal stays beneath its storage pins and reports partial failures."""

import contextlib
import errno
import os
import stat
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import dirfd, paths, progress
from chroot_distro.commands import remove
from chroot_distro.exceptions import ChrootDistroError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="uses Linux directory descriptors")


@pytest.fixture(params=["linux", "termux"])
def store(request, tmp_path, monkeypatch):
    anchor = tmp_path / "anchor"
    runtime = anchor / ("var/lib/chroot-distro" if request.param == "termux" else "chroot-distro")
    rootfs = runtime / "containers/box/rootfs"
    data = runtime / "data/box"
    rootfs.mkdir(parents=True)
    data.mkdir(parents=True)
    (rootfs / "kept").write_text("guest")
    (data / "run.log").write_text("log")
    monkeypatch.setattr(paths, "IS_TERMUX", request.param == "termux")
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(runtime / "containers"))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(remove, "ContainerLock", lambda *args, **kwargs: contextlib.nullcontext())
    monkeypatch.setattr(remove.session, "get_active_chroot_pids", lambda name: [])
    monkeypatch.setattr(remove.namespace, "get_live_holder", lambda name: None)
    monkeypatch.setattr(remove.mount_manager, "unmount_all", Mock())
    monkeypatch.setattr(remove.mount_manager, "get_active_mounts", lambda root: [])
    monkeypatch.setattr(progress, "progress_active", lambda: False)
    return SimpleNamespace(anchor=anchor, runtime=runtime, rootfs=rootfs, data=data, platform=request.param)


def run_remove(verbose=False):
    remove.command_remove(SimpleNamespace(container_name="box", verbose=verbose))


@pytest.mark.parametrize("part", ["runtime", "containers", "container", "rootfs", "data", "var"])
def test_remove_refuses_storage_links_before_deletion(store, tmp_path, monkeypatch, part):
    if part == "var" and store.platform != "termux":
        pytest.skip("var is below the Termux anchor")
    target = {
        "runtime": store.runtime,
        "containers": store.rootfs.parent.parent,
        "container": store.rootfs.parent,
        "rootfs": store.rootfs,
        "data": store.data.parent,
        "var": store.anchor / "var",
    }[part]
    moved = tmp_path / "external"
    target.rename(moved)
    target.symlink_to(moved, target_is_directory=True)
    sentinel = moved / "host"
    sentinel.write_text("KEEP")
    sentinel.chmod(0o400)
    with pytest.raises(ChrootDistroError):
        run_remove()
    assert sentinel.read_text() == "KEEP"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o400
    assert store.rootfs.is_dir()
    remove.mount_manager.unmount_all.assert_not_called()


def test_remove_clears_both_trees_and_keeps_other_names(store):
    other = store.data.parent / "other"
    other.mkdir()
    (other / "state").write_text("KEEP")
    (store.rootfs.parent / ".install-incomplete").touch()
    run_remove()
    assert not store.rootfs.parent.exists()
    assert not store.data.exists()
    assert (other / "state").read_text() == "KEEP"


@pytest.mark.parametrize("when", ["count", "delete"])
@pytest.mark.parametrize("part", ["data", "containers", "runtime"])
def test_remove_retains_parents_after_replacement(store, tmp_path, monkeypatch, part, when):
    target = {"data": store.data.parent, "containers": store.rootfs.parent.parent, "runtime": store.runtime}[part]
    moved = target.with_name(target.name + ".old")
    outside = tmp_path / "external"
    (outside / "box/rootfs").mkdir(parents=True)
    (outside / "box/rootfs/keep").write_text("KEEP")
    (outside / "box/state").write_text("KEEP")
    switched = False

    def switch():
        nonlocal switched
        if switched:
            return
        target.rename(moved)
        target.symlink_to(outside, target_is_directory=True)
        switched = True

    if when == "count":
        monkeypatch.setattr(progress, "progress_active", lambda: True)
        monkeypatch.setattr(progress, "draw_count_bar", Mock())
        monkeypatch.setattr(progress, "clear_bar", Mock())
        real_count = remove._count_files

        def count(path, **kwargs):
            result = real_count(path, **kwargs)
            if path == str(store.data):
                switch()
            return result

        monkeypatch.setattr(remove, "_count_files", count)
    else:
        real_remove = remove._remove_path

        def deleting(path, *args, **kwargs):
            switch()
            return real_remove(path, *args, **kwargs)

        monkeypatch.setattr(remove, "_remove_path", deleting)
    run_remove()
    assert switched
    assert (outside / "box/rootfs/keep").read_text() == "KEEP"
    assert (outside / "box/state").read_text() == "KEEP"
    if part == "runtime":
        assert not (moved / "data/box").exists()
        assert not (moved / "containers/box").exists()
    else:
        assert not (moved / "box").exists()
    if when == "count":
        progress.clear_bar.assert_called_once()


@pytest.mark.parametrize("where", ["data", "rootfs"])
def test_remove_unlinks_hardlinks_and_special_entries_without_host_changes(store, tmp_path, where):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    victim.chmod(0o400)
    tree = getattr(store, where)
    os.link(victim, tree / "hardlink")
    (tree / "symlink").symlink_to(victim)
    (tree / "directory-link").symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(tree / "fifo")
    run_remove()
    assert victim.read_text() == "KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o400
    assert victim.stat().st_nlink == 1


def test_final_runtime_link_is_unlinked_after_teardown(store, tmp_path, monkeypatch):
    outside = tmp_path / "host"
    outside.mkdir()
    (outside / "keep").write_text("KEEP")
    real_open = remove.open_runtime_data_dir
    moved = store.data.with_name("original")

    def opening():
        fd = real_open()
        store.data.rename(moved)
        store.data.symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(remove, "open_runtime_data_dir", opening)
    run_remove()
    assert not store.data.is_symlink()
    assert (outside / "keep").read_text() == "KEEP"
    assert (moved / "run.log").read_text() == "log"


def test_runtime_failure_keeps_container_and_allows_retry(store, monkeypatch, capsys):
    stuck = store.data / "stuck"
    stuck.write_text("state")
    real_unlink = dirfd._unlink_at

    def unlink(fd, name, *args):
        if name == "stuck":
            raise PermissionError(errno.EACCES, "injected failure")
        return real_unlink(fd, name, *args)

    with monkeypatch.context() as m:
        m.setattr(dirfd, "_unlink_at", unlink)
        with pytest.raises(SystemExit) as exc:
            run_remove()
    assert exc.value.code == 1
    assert (store.rootfs / "kept").read_text() == "guest"
    assert stuck.read_text() == "state"
    assert "Finished removing" not in capsys.readouterr().err
    run_remove()
    assert not store.data.exists()
    assert not store.rootfs.parent.exists()


def test_missing_runtime_data_after_teardown_is_ordinary_absence(store, monkeypatch):
    dirfd_fd = dirfd.opendir(str(store.runtime))
    try:
        dirfd.rmtree_at(dirfd_fd, "data")
    finally:
        os.close(dirfd_fd)
    monkeypatch.setattr(remove.session, "reset", Mock())
    monkeypatch.setattr(remove.session, "clear_mount_options", Mock())
    run_remove()
    assert not store.rootfs.parent.exists()


@pytest.mark.parametrize("point", ["runtime-open", "count", "callback"])
def test_interruption_closes_pins_and_clears_active_progress(store, monkeypatch, point):
    monkeypatch.setattr(remove.session, "reset", Mock())
    monkeypatch.setattr(remove.session, "clear_mount_options", Mock())
    monkeypatch.setattr(progress, "progress_active", lambda: True)
    clear = Mock()
    monkeypatch.setattr(progress, "clear_bar", clear)
    live = set()
    real_open, real_close = os.open, os.close

    def opening(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        live.add(fd)
        return fd

    def closing(fd):
        real_close(fd)
        live.discard(fd)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "close", closing)
    if point == "runtime-open":
        monkeypatch.setattr(remove, "open_runtime_data_dir", interrupt)
    elif point == "count":
        monkeypatch.setattr(dirfd, "count_tree_at", interrupt)
    else:
        monkeypatch.setattr(progress, "draw_count_bar", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_remove()
    assert not live
    assert store.rootfs.exists()
    if point == "callback":
        clear.assert_called_once()


def test_deep_restrictive_runtime_tree_is_counted_and_removed(store, monkeypatch):
    fd = dirfd.opendir(str(store.data))
    try:
        for _ in range(1105):
            os.mkdir("d", dir_fd=fd)
            child = dirfd.opendir_at(fd, "d")
            os.fchmod(fd, 0o500)
            os.close(fd)
            fd = child
        os.fchmod(fd, 0)
    finally:
        os.close(fd)
    store.data.chmod(0o700)
    monkeypatch.setattr(progress, "progress_active", lambda: True)
    monkeypatch.setattr(progress, "draw_count_bar", Mock())
    monkeypatch.setattr(progress, "clear_bar", Mock())
    try:
        run_remove()
        assert not store.data.exists()
        assert not store.rootfs.parent.exists()
        progress.clear_bar.assert_called_once()
    finally:
        remove._remove_path(str(store.runtime))


def test_verbose_paths_escape_controls(store, capsys):
    (store.data / "bad\n\x1b[31m").touch()
    run_remove(verbose=True)
    output = capsys.readouterr().err
    assert r"bad\n\e[31m" in output
    assert "bad\n\x1b" not in output


def test_path_helper_keeps_reset_call_form_and_callbacks(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "nested").mkdir(parents=True)
    (rootfs / "nested/file").touch()
    removed = []
    assert remove._remove_path(str(rootfs), removed.append)
    assert removed == [str(rootfs / "nested/file"), str(rootfs / "nested"), str(rootfs)]
    assert remove._remove_path(str(rootfs))


def test_helper_reports_access_errors_instead_of_missing_entries(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError(errno.EACCES, "injected refusal")

    monkeypatch.setattr(dirfd, "lstat_at", denied)
    assert remove._remove_path(str(tmp_path / "blocked")) is False


def test_runtime_parent_link_planted_after_teardown_is_refused(store, tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    (outside / "box").mkdir(parents=True)
    (outside / "box/keep").write_text("KEEP")
    original = store.data.parent.with_name("old-data")

    def mounts(rootfs):
        store.data.parent.rename(original)
        store.data.parent.symlink_to(outside, target_is_directory=True)
        return []

    monkeypatch.setattr(remove.mount_manager, "get_active_mounts", mounts)
    with pytest.raises(ChrootDistroError, match="Cannot open runtime data"):
        run_remove()
    assert (store.rootfs / "kept").read_text() == "guest"
    assert (outside / "box/keep").read_text() == "KEEP"
    assert (original / "box/run.log").read_text() == "log"


def test_runtime_io_refusal_preserves_both_trees(store, monkeypatch):
    def denied():
        raise PermissionError(errno.EACCES, "injected refusal")

    monkeypatch.setattr(remove, "open_runtime_data_dir", denied)
    with pytest.raises(ChrootDistroError, match="Cannot open runtime data"):
        run_remove()
    assert (store.rootfs / "kept").read_text() == "guest"
    assert (store.data / "run.log").read_text() == "log"


def test_directory_substituted_before_open_cannot_redirect_delete(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "guest").touch()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("KEEP")
    original = tmp_path / "original"
    real_open = dirfd._opendir_for_removal

    def opening(fd, name, st, force):
        tree.rename(original)
        tree.symlink_to(outside, target_is_directory=True)
        return real_open(fd, name, st, force)

    monkeypatch.setattr(dirfd, "_opendir_for_removal", opening)
    assert remove._remove_path(str(tree)) is False
    assert (outside / "keep").read_text() == "KEEP"
    assert (original / "guest").exists()
