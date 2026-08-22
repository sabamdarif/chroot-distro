"""Tests for `chroot-distro sync`, the mirror-and-prune side of the port.

These drive `_do_sync` directly, so no container lock is taken. The cases are the
rules that are easy to get wrong on a second pass: what counts as up to date,
what may be written in place, and what `--delete` is allowed to call an orphan.
"""

import contextlib
import errno
import os
import stat
import sys

import pytest

from chroot_distro import dirfd
from chroot_distro.commands.sync import (
    _META_FIXED,
    _META_OK,
    _META_REWRITE,
    _do_sync,
    _refresh_file_metadata,
)
from chroot_distro.exceptions import ChrootDistroError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="needs openat(2) semantics")


@pytest.fixture
def rootfs(tmp_path, monkeypatch):
    """An installed container named `distro`, addressable as `distro:/...`."""
    containers = tmp_path / "containers"
    root = containers / "distro" / "rootfs"
    root.mkdir(parents=True)
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))
    return root


@contextlib.contextmanager
def opened(path):
    """A readable directory fd for *path*, closed on the way out."""
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


def sync(src, dest, *, verbose=False, checksum=False, delete=False, chown=None):
    """Run the command, returning its exit status (0 when it did not exit)."""
    try:
        _do_sync(str(src), str(dest), verbose, checksum, delete, chown)
    except SystemExit as exc:
        return exc.code
    return 0


def _tree(root):
    """A source tree with a file, a nested file and a relative symlink."""
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "sub" / "b.txt").write_text("beta")
    os.symlink("a.txt", root / "link")
    return root


# ── mirroring ─────────────────────────────────────────────────────────────────
def test_a_tree_is_mirrored_and_the_second_run_rewrites_nothing(rootfs, tmp_path):
    src = _tree(tmp_path / "src")

    assert sync(src, "distro:/mirror") == 0
    dest = rootfs / "mirror"
    assert dest.joinpath("a.txt").read_text() == "alpha"
    assert dest.joinpath("sub", "b.txt").read_text() == "beta"
    assert os.readlink(dest / "link") == "a.txt"

    before = os.stat(dest / "a.txt").st_ino
    assert sync(src, "distro:/mirror") == 0
    # Same type, size and whole-second mtime: nothing to do, so the destination
    # inode survives. A rewrite would show up as a new one.
    assert os.stat(dest / "a.txt").st_ino == before


def test_a_mode_change_alone_is_applied_without_rewriting_the_file(rootfs, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    assert sync(src, "distro:/mirror") == 0
    dest = rootfs / "mirror" / "a.txt"
    before = os.stat(dest).st_ino

    os.chmod(src / "a.txt", 0o640)
    assert sync(src, "distro:/mirror") == 0

    # Change detection never looks at permissions, so a chmod with no other change
    # has to be caught by the metadata refresh or it would never arrive.
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o640
    assert os.stat(dest).st_ino == before


def test_a_hardlinked_destination_is_rewritten_rather_than_chmodded(rootfs, tmp_path):
    """The one case where fixing metadata in place would touch a foreign inode.

    A guest can hardlink a host file into its rootfs under the name a mirror is
    about to refresh; nothing about the entry says so, so the refresh is declined
    and the file is replaced through the temp-and-rename path instead.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    assert sync(src, "distro:/mirror") == 0
    dest = rootfs / "mirror" / "a.txt"
    victim = tmp_path / "host-secret"
    os.link(dest, victim)
    os.chmod(victim, 0o600)
    before = os.stat(dest).st_ino

    os.chmod(src / "a.txt", 0o640)
    assert sync(src, "distro:/mirror") == 0

    assert os.stat(dest).st_ino != before
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o640
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o600


def test_a_destination_entry_of_the_wrong_type_is_replaced(rootfs, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    os.symlink("elsewhere", src / "entry")
    mirror = rootfs / "mirror"
    mirror.mkdir()
    (mirror / "entry").write_text("was a file")

    assert sync(src, "distro:/mirror") == 0
    assert os.readlink(mirror / "entry") == "elsewhere"


def test_a_destination_directory_is_not_replaced_by_a_file(rootfs, tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "entry").write_text("alpha")
    mirror = rootfs / "mirror"
    (mirror / "entry").mkdir(parents=True)
    (mirror / "entry" / "keep.txt").write_text("kept")

    assert sync(src, "distro:/mirror") == 1
    assert "cannot replace directory" in capsys.readouterr().err
    assert (mirror / "entry" / "keep.txt").read_text() == "kept"


def test_a_special_file_inside_a_tree_is_reported_but_does_not_fail_the_run(rootfs, tmp_path, capsys):
    # A FIFO is a deliberate omission rather than a failure, as it is for `copy`:
    # no tree this command writes carries one, so the rest of the mirror stands.
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    os.mkfifo(src / "pipe")

    assert sync(src, "distro:/mirror") == 0
    assert "skipping special file" in capsys.readouterr().err
    assert (rootfs / "mirror" / "a.txt").read_text() == "alpha"
    assert not (rootfs / "mirror" / "pipe").exists()


def test_a_special_file_as_the_whole_source_is_refused(rootfs, tmp_path, capsys):
    os.mkfifo(tmp_path / "pipe")
    assert sync(tmp_path / "pipe", "distro:/pipe") == 1
    assert "not a regular file or directory" in capsys.readouterr().err


def test_a_single_file_synced_onto_a_directory_lands_inside_it(rootfs, tmp_path):
    (rootfs / "etc").mkdir()
    src = tmp_path / "hosts"
    src.write_text("127.0.0.1 localhost\n")

    assert sync(src, "distro:/etc") == 0
    assert (rootfs / "etc" / "hosts").read_text() == "127.0.0.1 localhost\n"


def test_checksum_catches_a_change_that_size_and_mtime_hide(rootfs, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    assert sync(src, "distro:/mirror") == 0
    dest = rootfs / "mirror" / "a.txt"

    (src / "a.txt").write_text("ALPHA")
    os.utime(src / "a.txt", (1_000_000, 1_000_000))
    os.utime(dest, (1_000_000, 1_000_000))

    assert sync(src, "distro:/mirror") == 0
    assert dest.read_text() == "alpha"
    assert sync(src, "distro:/mirror", checksum=True) == 0
    assert dest.read_text() == "ALPHA"


def test_a_missing_source_is_refused(rootfs, tmp_path, capsys):
    assert sync(tmp_path / "absent", "distro:/mirror") == 1
    assert "does not exist" in capsys.readouterr().err
    assert not (rootfs / "mirror").exists()


# ── --delete ──────────────────────────────────────────────────────────────────
def test_delete_prunes_what_the_source_has_no_counterpart_for(rootfs, tmp_path):
    src = _tree(tmp_path / "src")
    mirror = rootfs / "mirror"
    (mirror / "stale" / "deep").mkdir(parents=True)
    (mirror / "stale" / "deep" / "old.txt").write_text("old")
    (mirror / "orphan.txt").write_text("old")

    assert sync(src, "distro:/mirror", delete=True) == 0
    assert sorted(os.listdir(mirror)) == ["a.txt", "link", "sub"]
    assert (mirror / "sub" / "b.txt").read_text() == "beta"
    # And the pass is idempotent: a second run finds nothing left to prune.
    assert sync(src, "distro:/mirror", delete=True) == 0
    assert sorted(os.listdir(mirror)) == ["a.txt", "link", "sub"]


def test_delete_leaves_alone_a_destination_the_mirror_could_not_write(rootfs, tmp_path):
    """A skipped entry has no counterpart to compare against, so it is not an orphan.

    Deleting it would throw away data on the strength of a transfer that never
    happened.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    os.mkfifo(src / "pipe")
    mirror = rootfs / "mirror"
    mirror.mkdir()
    (mirror / "pipe").write_text("older payload")

    assert sync(src, "distro:/mirror", delete=True) == 0
    assert (mirror / "pipe").read_text() == "older payload"


def test_delete_declines_when_the_source_root_could_not_be_listed(rootfs, tmp_path, monkeypatch, capsys):
    """An unlistable source leaves every destination entry looking like an orphan."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    mirror = rootfs / "mirror"
    mirror.mkdir()
    (mirror / "keep.txt").write_text("kept")

    real_listdir = dirfd.listdir_at
    calls = []

    def fail_first(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(errno.EACCES, os.strerror(errno.EACCES))
        return real_listdir(fd)

    monkeypatch.setattr(dirfd, "listdir_at", fail_first)

    assert sync(src, "distro:/mirror", delete=True) == 1
    assert "not deleting anything" in capsys.readouterr().err
    assert (mirror / "keep.txt").read_text() == "kept"


def test_delete_needs_a_directory_source(rootfs, tmp_path, capsys):
    src = tmp_path / "a.txt"
    src.write_text("alpha")
    assert sync(src, "distro:/a.txt", delete=True) == 1
    assert "needs a directory as the source" in capsys.readouterr().err


def test_delete_refuses_a_source_sitting_inside_the_destination(rootfs):
    """Otherwise the source is itself one of the destination's orphans."""
    (rootfs / "data" / "inner").mkdir(parents=True)
    (rootfs / "data" / "inner" / "f.txt").write_text("payload")

    with pytest.raises(ChrootDistroError):
        sync("distro:/data/inner", "distro:/data", delete=True)
    assert (rootfs / "data" / "inner" / "f.txt").read_text() == "payload"


# ── reporting ─────────────────────────────────────────────────────────────────
def test_a_symlink_named_as_the_source_is_followed(rootfs, tmp_path, capsys):
    target = tmp_path / "target.txt"
    target.write_text("payload")
    os.symlink(str(target), tmp_path / "link")

    # Only the endpoints are followed — `sync /sdcard box:/x` is the ordinary way
    # to ask for this on Termux — so a dangling one has nothing to transfer.
    assert sync(tmp_path / "link", "distro:/copy.txt") == 0
    assert (rootfs / "copy.txt").read_text() == "payload"

    os.symlink("nowhere", tmp_path / "dangling")
    assert sync(tmp_path / "dangling", "distro:/dangling") == 1
    assert "does not exist" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="root is not stopped by file modes")
def test_an_unreadable_source_directory_is_refused_up_front(rootfs, tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    os.chmod(src, 0o000)
    try:
        assert sync(src, "distro:/mirror") == 1
    finally:
        os.chmod(src, 0o700)
    assert "is not readable" in capsys.readouterr().err
    assert not (rootfs / "mirror").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root is not stopped by file modes")
def test_an_unreadable_subdirectory_is_reported_and_its_mirror_left_alone(rootfs, tmp_path, capsys):
    src = tmp_path / "src"
    (src / "closed").mkdir(parents=True)
    (src / "a.txt").write_text("alpha")
    mirror = rootfs / "mirror"
    (mirror / "closed").mkdir(parents=True)
    (mirror / "closed" / "keep.txt").write_text("kept")
    os.chmod(src / "closed", 0o000)

    try:
        assert sync(src, "distro:/mirror", delete=True) == 1
    finally:
        os.chmod(src / "closed", 0o700)

    assert "is not readable, skipping" in capsys.readouterr().err
    assert (mirror / "a.txt").read_text() == "alpha"
    # The subtree has no counterpart to compare against, so `--delete` must not
    # take it as an orphan.
    assert (mirror / "closed" / "keep.txt").read_text() == "kept"


def test_verbose_names_what_it_writes_and_what_it_removes(rootfs, tmp_path, capsys):
    src = _tree(tmp_path / "src")
    mirror = rootfs / "mirror"
    mirror.mkdir()
    (mirror / "orphan.txt").write_text("old")

    assert sync(src, "distro:/mirror", verbose=True, delete=True) == 0
    err = capsys.readouterr().err
    assert "New file: " in err
    assert "New directory: " in err
    assert "New symlink: " in err
    assert "Delete: " in err

    (src / "a.txt").write_text("alpha again")
    assert sync(src, "distro:/mirror", verbose=True) == 0
    assert "Modified file: " in capsys.readouterr().err


def test_command_sync_holds_the_container_lock_while_it_runs(rootfs, tmp_path, monkeypatch):
    """The CLI entry point wraps _do_sync in the locks for both endpoints."""
    from argparse import Namespace

    from chroot_distro.commands.sync import command_sync

    locks = tmp_path / "locks"
    locks.mkdir()
    monkeypatch.setattr("chroot_distro.locking.LOCKS_DIR", str(locks))
    src = _tree(tmp_path / "src")

    command_sync(
        Namespace(source=str(src), destination="distro:/mirror", verbose=False, checksum=False, delete=True)
    )

    assert (rootfs / "mirror" / "sub" / "b.txt").read_text() == "beta"
    assert os.listdir(locks) == ["distro.lock"]


# ── ownership ─────────────────────────────────────────────────────────────────
def _with_owner(st, uid, gid):
    """*st* with its uid and gid replaced, everything else as it stands."""
    fields = list(st)
    fields[4] = uid
    fields[5] = gid
    return os.stat_result(tuple(fields))


def test_a_changed_owner_is_applied_without_rewriting_the_file(tmp_path, monkeypatch):
    """Ownership is metadata, so it is fixed on the inode, not by re-copying.

    Only root can hand a file to another user, and the unit suite does not run as
    root, so the source's ids are faked and the fchown recorded.
    """
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.txt").write_text("alpha")
    src_st = _with_owner(os.stat(dest / "a.txt"), 4242, 4243)
    before = os.stat(dest / "a.txt").st_ino
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))

    with opened(dest) as fd:
        assert _refresh_file_metadata(src_st, fd, "a.txt") == _META_FIXED

    assert calls == [(4242, 4243)]
    assert os.stat(dest / "a.txt").st_ino == before
    assert (dest / "a.txt").read_text() == "alpha"


def test_a_destination_that_cannot_hold_an_owner_is_not_reported_every_run(tmp_path, monkeypatch):
    # A vfat destination (/sdcard) refuses every chown, and nothing else about the
    # entry is out of date, so calling it modified would name the same file on
    # every sync for good.
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.txt").write_text("alpha")
    src_st = _with_owner(os.stat(dest / "a.txt"), 4242, 4243)

    def refuse(*_args):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(os, "fchown", refuse)
    with opened(dest) as fd:
        assert _refresh_file_metadata(src_st, fd, "a.txt") == _META_OK


def test_a_hardlinked_destination_is_not_chowned_either(tmp_path, monkeypatch):
    # The nlink rule outranks the owner fix for the same reason it outranks the
    # mode fix: the inode may be a host file the guest linked in.
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.txt").write_text("alpha")
    os.link(dest / "a.txt", tmp_path / "host-secret")
    src_st = _with_owner(os.stat(dest / "a.txt"), 4242, 4243)
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))

    with opened(dest) as fd:
        assert _refresh_file_metadata(src_st, fd, "a.txt") == _META_REWRITE
    assert calls == []


# ── --chown ───────────────────────────────────────────────────────────────────
def test_chown_stands_in_for_the_sources_ids_on_every_entry(rootfs, tmp_path, monkeypatch):
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "passwd").write_text("app:x:1002:1500:app:/home/app:/bin/sh\n")
    src = _tree(tmp_path / "src")
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    monkeypatch.setattr(
        os,
        "chown",
        lambda name, uid, gid, dir_fd=None, follow_symlinks=True: calls.append((uid, gid)),
    )

    assert sync(src, "distro:/opt/dest", chown="app") == 0

    assert (rootfs / "opt" / "dest" / "sub" / "b.txt").read_text() == "beta"
    assert set(calls) == {(1002, 1500)}


def test_a_group_alone_leaves_the_destinations_own_user_in_place(tmp_path, monkeypatch):
    """`--chown :GROUP` reaches _refresh_file_metadata as -1 for the uid.

    The sentinel must not be compared against the destination's own uid, or every
    run would find the entry misowned and report it as modified for good.
    """
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.txt").write_text("alpha")
    src_st = os.stat(dest / "a.txt")
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))

    with opened(dest) as fd:
        assert _refresh_file_metadata(src_st, fd, "a.txt", (-1, 4243)) == _META_FIXED
    assert calls == [(src_st.st_uid, 4243)]


def test_a_destination_already_carrying_the_requested_owner_is_left_alone(tmp_path, monkeypatch):
    # Without --chown the source's ids decide, and they differ from the
    # destination's here; the flag is what makes the entry already correct.
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.txt").write_text("alpha")
    dst_st = os.stat(dest / "a.txt")
    src_st = _with_owner(dst_st, 4242, 4243)
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))

    with opened(dest) as fd:
        assert _refresh_file_metadata(src_st, fd, "a.txt", (dst_st.st_uid, dst_st.st_gid)) == _META_OK
    assert calls == []


def test_an_unknown_chown_name_is_refused_before_anything_is_synced(rootfs, tmp_path):
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "passwd").write_text("app:x:1002:1500:app:/home/app:/bin/sh\n")
    src = _tree(tmp_path / "src")

    with pytest.raises(ChrootDistroError, match="unknown user 'ghost'"):
        sync(src, "distro:/opt/dest", chown="ghost")
    assert not (rootfs / "opt").exists()
