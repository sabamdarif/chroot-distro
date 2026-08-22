"""Tests for `chroot-distro copy`, the cp/mv side of the descriptor-pinned layer.

These drive `_do_copy` rather than `command_copy` so no container lock is taken;
the lock pairing itself is covered by test_paths.test_container_locks_for_spec_pair.
Each case is a rule the command inherits from cp or mv, or one of the guest-hostile
cases the pinning exists for: a name that turned into a symlink, a hardlink
planted where a write is about to land, endpoints that secretly overlap.
"""

import contextlib
import errno
import os
import stat
import sys

import pytest

from chroot_distro.commands.copy import _do_copy
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


def copy(src, dest, *, verbose=False, move=False, recursive=False, chown=None):
    """Run the command, returning its exit status (0 when it did not exit)."""
    try:
        _do_copy(str(src), str(dest), verbose, move, recursive, chown)
    except SystemExit as exc:
        return exc.code
    return 0


# ── cp semantics ──────────────────────────────────────────────────────────────
def test_recursive_copy_keeps_symlinks_modes_and_reports_special_files(rootfs, tmp_path, capsys):
    src = tmp_path / "payload"
    src.mkdir()
    (src / "f.txt").write_text("data")
    os.chmod(src / "f.txt", 0o640)
    os.symlink("f.txt", src / "link")
    os.mkfifo(src / "pipe")

    assert copy(src, "distro:/opt/payload", recursive=True) == 0

    landed = rootfs / "opt" / "payload"
    assert (landed / "f.txt").read_text() == "data"
    assert stat.S_IMODE(os.stat(landed / "f.txt").st_mode) == 0o640
    assert os.readlink(landed / "link") == "f.txt"
    # A FIFO cannot be recreated by a data copy, so it is named and stepped over.
    # cp -r reports it the same way and still succeeds.
    assert "skipping special file" in capsys.readouterr().err
    assert not (landed / "pipe").exists()


def test_a_directory_source_needs_recursive(rootfs, tmp_path, capsys):
    src = tmp_path / "dir"
    src.mkdir()
    assert copy(src, "distro:/opt/dir") == 1
    assert "--recursive" in capsys.readouterr().err
    assert not (rootfs / "opt").exists()


def test_a_copy_onto_a_directory_lands_inside_it(rootfs, tmp_path):
    (rootfs / "opt").mkdir()
    src = tmp_path / "f.txt"
    src.write_text("data")

    assert copy(src, "distro:/opt") == 0
    assert (rootfs / "opt" / "f.txt").read_text() == "data"


def test_a_missing_source_is_refused_before_anything_is_created(rootfs, tmp_path, capsys):
    assert copy(tmp_path / "absent", "distro:/opt/f.txt") == 1
    assert "does not exist" in capsys.readouterr().err
    assert not (rootfs / "opt").exists()


def test_copying_a_file_onto_itself_is_refused(rootfs):
    (rootfs / "f.txt").write_text("data")
    # cp refuses this because the destination is opened while the source is still
    # being read, which would leave an empty file behind.
    with pytest.raises(ChrootDistroError, match="same file"):
        copy("distro:/f.txt", "distro:/f.txt")
    assert (rootfs / "f.txt").read_text() == "data"


def test_a_directory_copied_into_itself_is_refused_before_it_recurses(rootfs):
    (rootfs / "tree" / "sub").mkdir(parents=True)
    (rootfs / "tree" / "f.txt").write_text("data")
    with pytest.raises(ChrootDistroError, match="into itself"):
        copy("distro:/tree", "distro:/tree/sub", recursive=True)
    assert os.listdir(rootfs / "tree" / "sub") == []


def test_a_guest_symlink_is_enough_to_make_two_specs_overlap(rootfs):
    """The overlap guard weighs the resolved paths, not the two strings typed."""
    (rootfs / "data").mkdir()
    (rootfs / "data" / "f.txt").write_text("data")
    os.symlink("/data", rootfs / "backup")
    with pytest.raises(ChrootDistroError):
        copy("distro:/data", "distro:/backup", recursive=True)


def test_a_container_file_can_be_copied_out_to_the_host(rootfs, tmp_path):
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "hosts").write_text("127.0.0.1 localhost\n")

    assert copy("distro:/etc/hosts", tmp_path / "hosts") == 0
    assert (tmp_path / "hosts").read_text() == "127.0.0.1 localhost\n"


# ── what the pinning is for ───────────────────────────────────────────────────
def test_an_absolute_symlink_in_the_container_resolves_inside_the_container(rootfs, tmp_path):
    """A guest symlink to /real-etc means the guest's /real-etc, as it would inside chroot."""
    (rootfs / "real-etc").mkdir()
    os.symlink("/real-etc", rootfs / "etc")
    src = tmp_path / "f.txt"
    src.write_text("guest")

    assert copy(src, "distro:/etc/f.txt") == 0
    assert (rootfs / "real-etc" / "f.txt").read_text() == "guest"


def test_a_symlink_out_of_the_rootfs_does_not_take_the_write_with_it(rootfs, tmp_path):
    outside = tmp_path / "host-etc"
    outside.mkdir()
    os.symlink(str(outside), rootfs / "escape")
    src = tmp_path / "f.txt"
    src.write_text("guest")

    assert copy(src, "distro:/escape/f.txt") == 0
    assert os.listdir(outside) == []


def test_a_planted_hardlink_at_the_destination_is_not_written_through(rootfs, tmp_path):
    """The one case O_NOFOLLOW cannot refuse: nothing about the entry is wrong.

    A guest that hardlinks a host file into its rootfs under the name a copy is
    about to write would otherwise have that host file overwritten with content
    it chose.
    """
    victim = tmp_path / "host-secret"
    victim.write_text("host data")
    os.link(victim, rootfs / "planted")
    src = tmp_path / "payload.txt"
    src.write_text("guest data")

    assert copy(src, "distro:/planted") == 0
    assert victim.read_text() == "host data"
    assert (rootfs / "planted").read_text() == "guest data"


# ── mv semantics ──────────────────────────────────────────────────────────────
def test_move_renames_the_link_itself_not_its_target(rootfs, tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("payload")
    link = tmp_path / "link"
    os.symlink(str(target), link)

    assert copy(link, "distro:/moved", move=True) == 0
    assert os.readlink(rootfs / "moved") == str(target)
    assert not os.path.lexists(link)
    assert target.read_text() == "payload"


def test_a_dangling_symlink_can_be_moved(rootfs, tmp_path):
    link = tmp_path / "link"
    os.symlink("nowhere", link)

    assert copy(link, "distro:/moved", move=True) == 0
    assert os.readlink(rootfs / "moved") == "nowhere"
    assert not os.path.lexists(link)


def test_move_replaces_a_destination_symlink_instead_of_writing_through_it(rootfs, tmp_path):
    victim = tmp_path / "host-secret"
    victim.write_text("host data")
    os.symlink(str(victim), rootfs / "planted")
    src = tmp_path / "payload.txt"
    src.write_text("guest data")

    assert copy(src, "distro:/planted", move=True) == 0
    assert victim.read_text() == "host data"
    assert not (rootfs / "planted").is_symlink()
    assert (rootfs / "planted").read_text() == "guest data"


def _refuse_rename_across_devices(monkeypatch):
    """Make rename(2) answer EXDEV, the one errno that has a fallback path.

    Termux's common move — a rootfs onto /sdcard — is always cross-device, and a
    unit test cannot mount a second filesystem.
    """

    def raise_exdev(*_args, **_kwargs):
        raise OSError(errno.EXDEV, os.strerror(errno.EXDEV))

    monkeypatch.setattr(os, "rename", raise_exdev)


def test_a_cross_device_move_copies_then_removes(rootfs, tmp_path, monkeypatch):
    src = tmp_path / "tree"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_text("data")
    os.symlink("sub/f.txt", src / "link")
    _refuse_rename_across_devices(monkeypatch)

    assert copy(src, "distro:/tree", move=True) == 0
    assert (rootfs / "tree" / "sub" / "f.txt").read_text() == "data"
    assert os.readlink(rootfs / "tree" / "link") == "sub/f.txt"
    assert not src.exists()


def test_a_cross_device_move_keeps_the_source_when_an_entry_did_not_make_it(
    rootfs, tmp_path, monkeypatch, capsys
):
    """A FIFO is a warning during a copy but silent data loss during a move."""
    src = tmp_path / "tree"
    src.mkdir()
    (src / "f.txt").write_text("data")
    os.mkfifo(src / "pipe")
    _refuse_rename_across_devices(monkeypatch)

    assert copy(src, "distro:/tree", move=True) == 1
    err = capsys.readouterr().err
    assert "skipping special file" in err
    assert "Source left in place" in err
    assert (src / "pipe").exists()
    assert (src / "f.txt").read_text() == "data"


# ── reporting ─────────────────────────────────────────────────────────────────
def test_a_fifo_named_as_the_whole_source_is_refused(rootfs, tmp_path, capsys):
    os.mkfifo(tmp_path / "pipe")
    assert copy(tmp_path / "pipe", "distro:/pipe") == 1
    assert "not a regular file or directory" in capsys.readouterr().err
    assert not (rootfs / "pipe").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root is not stopped by file modes")
def test_an_unreadable_entry_costs_only_itself(rootfs, tmp_path, capsys):
    src = tmp_path / "tree"
    src.mkdir()
    (src / "readable.txt").write_text("data")
    (src / "closed.txt").write_text("secret")
    os.chmod(src / "closed.txt", 0o000)

    # cp -r reports the entry and carries on, then exits non-zero.
    assert copy(src, "distro:/tree", recursive=True) == 1
    err = capsys.readouterr().err
    assert "cannot copy" in err
    assert "1 entry could not be copied" in err
    assert (rootfs / "tree" / "readable.txt").read_text() == "data"


@pytest.mark.skipif(os.geteuid() == 0, reason="root is not stopped by file modes")
def test_an_unreadable_source_is_refused_up_front(rootfs, tmp_path, capsys):
    src = tmp_path / "closed.txt"
    src.write_text("secret")
    os.chmod(src, 0o000)

    assert copy(src, "distro:/f.txt") == 1
    assert "is not readable" in capsys.readouterr().err
    assert not (rootfs / "f.txt").exists()


def test_a_non_regular_destination_is_not_written_over(rootfs, tmp_path, capsys):
    os.mkfifo(rootfs / "pipe")
    src = tmp_path / "f.txt"
    src.write_text("data")

    assert copy(src, "distro:/pipe") == 1
    assert capsys.readouterr().err
    assert stat.S_ISFIFO(os.stat(rootfs / "pipe").st_mode)


def test_verbose_names_every_entry_as_it_goes(rootfs, tmp_path, capsys):
    src = tmp_path / "tree"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "b.txt").write_text("beta")

    assert copy(src, "distro:/tree", recursive=True, verbose=True) == 0
    err = capsys.readouterr().err
    assert "Copying: '" in err
    assert "sub/b.txt" in err

    assert copy(src / "sub" / "b.txt", "distro:/b.txt", verbose=True) == 0
    assert "Copying: '" in capsys.readouterr().err

    assert copy(src / "sub" / "b.txt", "distro:/moved.txt", move=True, verbose=True) == 0
    assert "Moving: '" in capsys.readouterr().err


def test_a_cross_device_move_recreates_a_symlink_rather_than_its_target(rootfs, tmp_path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text("payload")
    link = tmp_path / "link"
    os.symlink(str(target), link)
    _refuse_rename_across_devices(monkeypatch)

    assert copy(link, "distro:/moved", move=True) == 0
    assert os.readlink(rootfs / "moved") == str(target)
    assert not os.path.lexists(link)
    assert target.read_text() == "payload"


def test_a_cross_device_move_of_a_single_file_clears_the_destination_name(rootfs, tmp_path, monkeypatch):
    victim = tmp_path / "host-secret"
    victim.write_text("host data")
    os.link(victim, rootfs / "planted")
    src = tmp_path / "payload.txt"
    src.write_text("guest data")
    _refuse_rename_across_devices(monkeypatch)

    # Off the rename fast path the destination name has to be unlinked by hand, or
    # the write would go through the planted link into the host's file.
    assert copy(src, "distro:/planted", move=True) == 0
    assert victim.read_text() == "host data"
    assert (rootfs / "planted").read_text() == "guest data"
    assert not src.exists()


def test_command_copy_holds_the_container_lock_while_it_runs(rootfs, tmp_path, monkeypatch):
    """The CLI entry point wraps _do_copy in the locks for both endpoints."""
    from argparse import Namespace

    from chroot_distro.commands.copy import command_copy

    locks = tmp_path / "locks"
    locks.mkdir()
    monkeypatch.setattr("chroot_distro.locking.LOCKS_DIR", str(locks))
    src = tmp_path / "f.txt"
    src.write_text("data")

    command_copy(Namespace(source=str(src), destination="distro:/f.txt", verbose=False, move=False, recursive=False))

    assert (rootfs / "f.txt").read_text() == "data"
    assert os.listdir(locks) == ["distro.lock"]


# ── --chown ───────────────────────────────────────────────────────────────────
def _guest_passwd(rootfs):
    """Give the container an `app` account, uid 1002 with primary group 1500."""
    (rootfs / "etc").mkdir(parents=True, exist_ok=True)
    (rootfs / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\napp:x:1002:1500:app:/home/app:/bin/sh\n")


@contextlib.contextmanager
def recorded_ownership(monkeypatch):
    """Record every ownership change as (uid, gid), performing none of them.

    A transfer runs as root; a test does not, so handing out ids for real would
    need a second uid to hand them to.
    """
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    monkeypatch.setattr(
        os,
        "chown",
        lambda name, uid, gid, dir_fd=None, follow_symlinks=True: calls.append((uid, gid)),
    )
    yield calls


def test_chown_resolves_the_name_in_the_container_and_uses_it_throughout(rootfs, tmp_path, monkeypatch):
    _guest_passwd(rootfs)
    src = tmp_path / "payload"
    src.mkdir()
    (src / "f.txt").write_text("data")
    os.symlink("f.txt", src / "link")

    with recorded_ownership(monkeypatch) as calls:
        assert copy(src, "distro:/opt/payload", recursive=True, chown="app") == 0

    # The directory, the file and the symlink all get the guest's numbers rather
    # than the host ids the source carries.
    assert (rootfs / "opt" / "payload" / "f.txt").read_text() == "data"
    assert len(calls) >= 3
    assert set(calls) == {(1002, 1500)}


def test_chown_reaches_a_move_that_was_only_a_rename(rootfs, tmp_path, monkeypatch):
    _guest_passwd(rootfs)
    src = rootfs / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_text("data")

    with recorded_ownership(monkeypatch) as calls:
        assert copy("distro:/src", "distro:/dst", move=True, chown="app") == 0

    # rename(2) writes nothing, so the only way the flag can reach the moved
    # inodes is the walk afterwards: the root, sub, and the file inside it.
    assert (rootfs / "dst" / "sub" / "f.txt").read_text() == "data"
    assert calls == [(1002, 1500)] * 3


def test_a_move_onto_a_filesystem_without_ownership_says_so_once(rootfs, tmp_path, monkeypatch, capsys):
    _guest_passwd(rootfs)
    src = rootfs / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_text("data")

    def refuse(*_args, **_kwargs):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(os, "chown", refuse)
    assert copy("distro:/src", "distro:/dst", move=True, chown="app") == 0

    # vfat holds no ownership, so every entry in the tree refuses; that is one
    # thing worth saying, not one per file.
    err = capsys.readouterr().err
    assert err.count("would not take the requested owner") == 1
    assert "3 entries" in err
    assert (rootfs / "dst" / "sub" / "f.txt").read_text() == "data"


def test_an_unknown_chown_name_is_refused_before_anything_is_copied(rootfs, tmp_path):
    _guest_passwd(rootfs)
    src = tmp_path / "f.txt"
    src.write_text("data")

    with pytest.raises(ChrootDistroError, match="unknown user 'ghost'"):
        copy(src, "distro:/opt/f.txt", chown="ghost")
    assert not (rootfs / "opt").exists()
