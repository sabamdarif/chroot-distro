"""Tests for chroot_distro.dirfd, the openat(2) layer `copy` and `sync` run on.

What is worth pinning down here is the handful of rules that do not follow from
the syscall names: O_NOFOLLOW says nothing about a FIFO, fchmod does not reach an
O_PATH descriptor, a hardlink looks exactly like an ordinary entry, and how deep
a tree goes is decided by whoever filled the container rather than by this code.
"""

import contextlib
import errno
import os
import signal
import stat
import sys

import pytest

from chroot_distro import dirfd

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="wraps Linux openat(2) semantics")

unprivileged_only = pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 1000)() == 0, reason="root is not stopped by file modes"
)


@contextlib.contextmanager
def opened(path):
    """A readable directory fd for *path*, closed on the way out."""
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


class _Blocked(Exception):
    """A call under deadline() did not return.

    Deliberately not an OSError: every caller in the tree turns an OSError into a
    tidy per-entry failure, which would make a blocked open look like a refusal.
    """


@contextlib.contextmanager
def deadline(seconds=5):
    """Turn a syscall that never returns into a failure rather than a hang."""

    def fire(_signum, _frame):
        raise _Blocked("call did not return")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _tree(root):
    """A small tree: two files, a symlink, and a subdirectory holding one more."""
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_text("beta")
    os.symlink("a.txt", root / "link")
    return root


# ── descending under a root ────────────────────────────────────────────────────
def test_makedirs_under_creates_every_level(tmp_path):
    made = dirfd.makedirs_under(str(tmp_path), ["a", "b", "c"], mode=0o701)
    assert made == str(tmp_path / "a" / "b" / "c")
    assert (tmp_path / "a" / "b" / "c").is_dir()
    assert stat.S_IMODE((tmp_path / "a" / "b" / "c").stat().st_mode) == 0o701


def test_makedirs_under_refuses_a_symlinked_component(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(str(outside), root / "x")

    assert dirfd.makedirs_under(str(root), ["x", "sub"]) is None
    assert os.listdir(str(outside)) == []


def test_opendir_under_without_create_reports_a_missing_level(tmp_path):
    assert dirfd.opendir_under(str(tmp_path), ["nope"]) is None


def test_descend_at_with_no_parts_hands_back_a_separate_descriptor(tmp_path):
    with opened(tmp_path) as fd:
        again = dirfd.descend_at(fd, [])
        try:
            assert again != fd
            assert os.fstat(again).st_ino == os.fstat(fd).st_ino
        finally:
            os.close(again)


# ── refusing what a name might have become ────────────────────────────────────
def test_opendir_at_refuses_a_symlinked_directory(tmp_path):
    (tmp_path / "real").mkdir()
    os.symlink("real", tmp_path / "link")
    with opened(tmp_path) as fd, pytest.raises(OSError) as exc:
        dirfd.opendir_at(fd, "link")
    # Linux answers O_NOFOLLOW|O_DIRECTORY on a symlink with ENOTDIR, not ELOOP,
    # which is why is_refusal() has to accept both.
    assert exc.value.errno in (errno.ELOOP, errno.ENOTDIR)
    assert dirfd.is_refusal(exc.value)


def test_open_regular_at_refuses_a_fifo_without_waiting_for_a_peer(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with opened(tmp_path) as fd, deadline():
        with pytest.raises(OSError) as writing:
            dirfd.open_regular_at(fd, "pipe", os.O_WRONLY)
        assert writing.value.errno == errno.ENXIO
        with pytest.raises(OSError) as reading:
            dirfd.open_regular_at(fd, "pipe", os.O_RDONLY)
        assert reading.value.errno == errno.EINVAL


def test_open_regular_at_refuses_a_directory(tmp_path):
    (tmp_path / "d").mkdir()
    with opened(tmp_path) as fd, pytest.raises(OSError):
        dirfd.open_regular_at(fd, "d", os.O_RDONLY)


def test_open_new_at_never_writes_through_a_hardlink(tmp_path):
    """The one thing O_NOFOLLOW cannot give: a planted link is not refusable.

    A guest that hardlinks a host file into its rootfs under the name a transfer
    is about to write leaves nothing about the entry to object to, so the create
    is O_EXCL and the leftover name is unlinked rather than opened.
    """
    victim = tmp_path / "victim"
    victim.write_text("host data")
    os.link(victim, tmp_path / "planted")

    with opened(tmp_path) as fd:
        new_fd, _ = dirfd.open_new_at(fd, "planted")
        try:
            os.write(new_fd, b"transferred")
        finally:
            os.close(new_fd)

    assert victim.read_text() == "host data"
    assert (tmp_path / "planted").read_text() == "transferred"
    assert os.stat(victim).st_ino != os.stat(tmp_path / "planted").st_ino


@pytest.mark.skipif(not getattr(os, "O_PATH", 0), reason="needs O_PATH")
def test_make_writable_reaches_an_o_path_descriptor(tmp_path):
    """paths.pin_path hands out O_PATH fds, where fchmod is EBADF.

    Every caller of make_writable() wraps its own retry in a permission
    recovery, so an fchmod that silently failed here would leave a copy into an
    unwritable directory reporting the error the call exists to clear.
    """
    d = tmp_path / "d"
    d.mkdir()
    os.chmod(d, 0o500)
    fd = os.open(str(d), dirfd._O_PATH_DIR)
    try:
        with pytest.raises(OSError) as exc:
            os.fchmod(fd, 0o700)
        assert exc.value.errno == errno.EBADF
        dirfd.make_writable(fd)
    finally:
        os.close(fd)
    assert stat.S_IMODE(os.stat(d).st_mode) & stat.S_IRWXU == stat.S_IRWXU


# ── names, data and metadata ──────────────────────────────────────────────────
def test_temp_name_trims_the_stem_to_fit_one_component():
    plain = dirfd.temp_name("f.txt", dirfd.TMP_SUFFIX)
    assert plain == "f.txt" + dirfd.TMP_SUFFIX

    long = dirfd.temp_name("x" * dirfd.NAME_MAX, dirfd.TMP_SUFFIX)
    assert len(os.fsencode(long)) == dirfd.NAME_MAX
    assert long.endswith(dirfd.TMP_SUFFIX)


def test_temp_name_trims_on_bytes_not_characters():
    # NAME_MAX counts bytes, so a name of multi-byte characters has to be cut on
    # the encoded form; a character cut in half comes back as surrogates that
    # re-encode to exactly the bytes it was cut to.
    name = "é" * dirfd.NAME_MAX
    trimmed = dirfd.temp_name(name, dirfd.TMP_SUFFIX)
    assert len(os.fsencode(trimmed)) == dirfd.NAME_MAX


def test_copy_file_at_preserves_mode_and_mtime(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    f = src / "f.txt"
    f.write_text("payload")
    os.chmod(f, 0o604)
    os.utime(f, (1_000_000, 1_000_000))

    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_file_at(sfd, "f.txt", dfd, "f.txt")

    copied = dst / "f.txt"
    assert copied.read_text() == "payload"
    assert stat.S_IMODE(os.stat(copied).st_mode) == 0o604
    assert int(os.stat(copied).st_mtime) == 1_000_000


def test_copy_file_at_replace_refuses_a_non_regular_destination(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "f.txt").write_text("x")
    os.mkfifo(dst / "f.txt")

    with opened(src) as sfd, opened(dst) as dfd, pytest.raises(OSError) as exc:
        dirfd.copy_file_at(sfd, "f.txt", dfd, "f.txt", replace=True)
    assert exc.value.errno == errno.EEXIST
    assert stat.S_ISFIFO(os.stat(dst / "f.txt").st_mode)


def test_copy_file_at_replace_leaves_the_old_file_when_the_write_fails(tmp_path, monkeypatch):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "f.txt").write_text("new")
    (dst / "f.txt").write_text("old")

    def boom(*_args, **_kwargs):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(dirfd, "copy_data", boom)
    with opened(src) as sfd, opened(dst) as dfd, pytest.raises(OSError):
        dirfd.copy_file_at(sfd, "f.txt", dfd, "f.txt", replace=True)

    assert (dst / "f.txt").read_text() == "old"
    assert os.listdir(dst) == ["f.txt"]


def test_copy_data_keeps_a_sparsely_stored_file_sparse(tmp_path):
    size = 4 << 20
    src = tmp_path / "sparse"
    with open(src, "wb") as fh:
        fh.truncate(size)
        fh.seek(size // 2)
        fh.write(b"data in the middle")
        fh.truncate(size)
    src_st = os.stat(src)
    if not dirfd._looks_sparse(src_st):
        pytest.skip("this filesystem does not store the file sparsely")

    with opened(tmp_path) as fd:
        dirfd.copy_file_at(fd, "sparse", fd, "copy", src_st)

    copy_st = os.stat(tmp_path / "copy")
    assert copy_st.st_size == size
    assert (tmp_path / "copy").read_bytes() == src.read_bytes()
    assert copy_st.st_blocks * 512 < size


def test_copy_data_invents_no_holes_in_a_dense_file(tmp_path):
    src = tmp_path / "dense"
    src.write_bytes(bytes(range(256)) * 4096)
    with opened(tmp_path) as fd:
        dirfd.copy_file_at(fd, "dense", fd, "copy")
    assert (tmp_path / "copy").read_bytes() == src.read_bytes()


# ── walking a tree ────────────────────────────────────────────────────────────
def test_count_tree_at_counts_entries_but_not_directories(tmp_path):
    # copy_tree_at reports a directory only once its contents are in, so counting
    # directories would leave the progress bar short of its own total.
    _tree(tmp_path / "src")
    with opened(tmp_path / "src") as fd:
        assert dirfd.count_tree_at(fd) == 3


def test_copy_tree_at_mirrors_files_symlinks_and_directory_modes(tmp_path):
    src = _tree(tmp_path / "src")
    os.chmod(src / "sub", 0o555)
    dst = tmp_path / "dst"
    dst.mkdir()
    written = []

    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_tree_at(sfd, dfd, on_entry=written.append)

    assert (dst / "a.txt").read_text() == "alpha"
    assert (dst / "sub" / "b.txt").read_text() == "beta"
    assert (dst / "link").is_symlink()
    assert os.readlink(dst / "link") == "a.txt"
    # A source directory that is not writable itself still gets its contents, and
    # comes out carrying its own mode.
    assert stat.S_IMODE(os.stat(dst / "sub").st_mode) == 0o555
    assert sorted(written) == ["a.txt", "link", "sub/b.txt"]


def test_copy_tree_at_does_not_descend_a_symlinked_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("host")
    src = tmp_path / "src"
    src.mkdir()
    os.symlink(str(outside), src / "escape")
    dst = tmp_path / "dst"
    dst.mkdir()

    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_tree_at(sfd, dfd)

    assert (dst / "escape").is_symlink()
    assert os.readlink(dst / "escape") == str(outside)
    assert sorted(os.listdir(dst)) == ["escape"]
    # Nothing was written through the link either: the host directory is untouched.
    assert sorted(os.listdir(outside)) == ["secret.txt"]


def test_copy_tree_at_reports_a_special_file_instead_of_copying_it(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("x")
    os.mkfifo(src / "pipe")
    dst = tmp_path / "dst"
    dst.mkdir()
    skipped = []

    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_tree_at(sfd, dfd, on_skip=skipped.append)

    assert skipped == ["pipe"]
    assert sorted(os.listdir(dst)) == ["f.txt"]


@unprivileged_only
def test_copy_tree_at_steps_over_an_unreadable_directory(tmp_path):
    src = tmp_path / "src"
    (src / "closed").mkdir(parents=True)
    (src / "closed" / "hidden.txt").write_text("x")
    (src / "open.txt").write_text("y")
    os.chmod(src / "closed", 0o000)
    dst = tmp_path / "dst"
    dst.mkdir()
    errors = []

    try:
        with opened(src) as sfd, opened(dst) as dfd:
            dirfd.copy_tree_at(sfd, dfd, on_error=lambda rel, exc: errors.append((rel, exc.errno)))
    finally:
        os.chmod(src / "closed", 0o700)

    # The point of the command is to save what can be saved, so the rest of the
    # tree still arrives and the caller is told what did not.
    assert errors == [("closed", errno.EACCES)]
    assert (dst / "open.txt").read_text() == "y"


@unprivileged_only
def test_copy_tree_at_without_on_error_still_raises(tmp_path):
    src = tmp_path / "src"
    (src / "closed").mkdir(parents=True)
    os.chmod(src / "closed", 0o000)
    dst = tmp_path / "dst"
    dst.mkdir()

    try:
        with opened(src) as sfd, opened(dst) as dfd, pytest.raises(OSError):
            dirfd.copy_tree_at(sfd, dfd)
    finally:
        os.chmod(src / "closed", 0o700)


def test_copy_tree_at_merges_only_when_asked(tmp_path):
    src = _tree(tmp_path / "src")
    (src / "sub" / "b.txt").write_text("fresh")
    dst = tmp_path / "dst"
    (dst / "sub").mkdir(parents=True)
    (dst / "sub" / "b.txt").write_text("stale")

    with opened(src) as sfd, opened(dst) as dfd, pytest.raises(FileExistsError):
        dirfd.copy_tree_at(sfd, dfd)

    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_tree_at(sfd, dfd, merge=True)
    assert (dst / "sub" / "b.txt").read_text() == "fresh"
    assert (dst / "a.txt").read_text() == "alpha"


def test_copy_tree_at_survives_a_tree_deeper_than_its_fd_budget(tmp_path, monkeypatch):
    """Past MAX_OPEN_LEVELS live levels the shallowest is parked and reopened.

    A container can nest directories faster than the soft descriptor limit
    allows one fd per level, so the budget is squeezed here rather than building
    a thousand-level tree in a unit test.
    """
    monkeypatch.setattr(dirfd, "MAX_OPEN_LEVELS", 2)
    src = tmp_path / "src"
    deep = src
    for i in range(12):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / "bottom.txt").write_text("floor")
    dst = tmp_path / "dst"
    dst.mkdir()

    with opened(src) as sfd:
        assert dirfd.count_tree_at(sfd) == 1
    with opened(src) as sfd, opened(dst) as dfd:
        dirfd.copy_tree_at(sfd, dfd)

    mirrored = dst
    for i in range(12):
        mirrored = mirrored / f"level{i}"
    assert (mirrored / "bottom.txt").read_text() == "floor"


# ── removing a tree ───────────────────────────────────────────────────────────
def test_rmtree_at_unlinks_a_symlink_without_following_it(tmp_path):
    keep = tmp_path / "keep"
    keep.mkdir()
    (keep / "file.txt").write_text("kept")
    doomed = tmp_path / "doomed"
    doomed.mkdir()
    os.symlink(str(keep), doomed / "link")

    with opened(tmp_path) as fd:
        assert dirfd.rmtree_at(fd, "doomed") is True

    assert not doomed.exists()
    assert (keep / "file.txt").read_text() == "kept"


@unprivileged_only
def test_rmtree_at_force_clears_an_unreadable_directory(tmp_path):
    root = tmp_path / "root"
    (root / "closed").mkdir(parents=True)
    (root / "closed" / "f.txt").write_text("x")
    os.chmod(root / "closed", 0o000)

    with opened(tmp_path) as fd:
        # Without force the directory cannot even be listed, so it stays.
        assert dirfd.rmtree_at(fd, "root", on_error=lambda _rel, _exc: None) is False
        assert root.exists()
        assert dirfd.rmtree_at(fd, "root", force=True) is True

    assert not root.exists()


def test_rmtree_at_reports_each_removal_and_each_failure(tmp_path, monkeypatch):
    root = _tree(tmp_path / "root")
    removed = []
    errors = []
    real_unlink = dirfd._unlink_at

    def refuse_one(dir_fd, name, is_dir, force):
        if name == "a.txt":
            raise OSError(errno.EPERM, os.strerror(errno.EPERM), name)
        real_unlink(dir_fd, name, is_dir, force)

    monkeypatch.setattr(dirfd, "_unlink_at", refuse_one)

    with opened(tmp_path) as fd:
        ok = dirfd.rmtree_at(
            fd,
            "root",
            on_remove=removed.append,
            on_error=lambda rel, exc: errors.append((rel, exc.errno)),
        )

    assert ok is False
    assert errors == [("a.txt", errno.EPERM)]
    # The rest of the tree still goes, and a directory is reported once its own
    # contents are gone.
    assert sorted(removed) == ["link", "sub", "sub/b.txt"]
    assert (root / "a.txt").exists()
    assert not (root / "sub").exists()


def test_rmtree_at_without_on_error_still_raises(tmp_path, monkeypatch):
    _tree(tmp_path / "root")
    def refuse(_dir_fd, name, _is_dir, _force):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM), name)

    monkeypatch.setattr(dirfd, "_unlink_at", refuse)

    with opened(tmp_path) as fd, pytest.raises(OSError):
        dirfd.rmtree_at(fd, "root")


def test_rmtree_at_is_content_with_a_name_that_is_already_gone(tmp_path):
    with opened(tmp_path) as fd:
        assert dirfd.rmtree_at(fd, "never-existed") is True


# ── ownership ─────────────────────────────────────────────────────────────────
def test_copy_metadata_sets_the_owner_before_the_mode(tmp_path, monkeypatch):
    """chown(2) drops setuid and setgid unless the caller holds CAP_FSETID.

    A transfer runs as root, where the two calls are both permitted and the
    order is the only thing deciding whether a setuid source arrives setuid.
    Asserting on real ids would need a second uid to give them to, so the calls
    are recorded instead.
    """
    (tmp_path / "src").write_text("payload")
    (tmp_path / "dst").write_text("")
    order = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: order.append(("chown", uid, gid)))
    monkeypatch.setattr(os, "fchmod", lambda fd, mode: order.append(("chmod", mode)))

    os.chmod(tmp_path / "src", 0o4755)
    src_st = os.stat(tmp_path / "src")
    sfd = os.open(str(tmp_path / "src"), os.O_RDONLY)
    dfd = os.open(str(tmp_path / "dst"), os.O_WRONLY)
    try:
        dirfd.copy_metadata(sfd, dfd, src_st)
    finally:
        os.close(dfd)
        os.close(sfd)

    assert order == [("chown", src_st.st_uid, src_st.st_gid), ("chmod", 0o4755)]


def test_copy_metadata_finishes_when_the_destination_holds_no_ownership(tmp_path, monkeypatch):
    # /sdcard is vfat, so a Termux move off the rootfs cannot set an owner. The
    # data is already written by this point; the mode and times still have to land.
    (tmp_path / "src").write_text("payload")
    os.chmod(tmp_path / "src", 0o640)
    os.utime(tmp_path / "src", (1_000_000, 1_000_000))
    (tmp_path / "dst").write_text("")

    def refuse(*_args):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(os, "fchown", refuse)
    sfd = os.open(str(tmp_path / "src"), os.O_RDONLY)
    dfd = os.open(str(tmp_path / "dst"), os.O_WRONLY)
    try:
        dirfd.copy_metadata(sfd, dfd, os.stat(tmp_path / "src"))
    finally:
        os.close(dfd)
        os.close(sfd)

    dst_st = os.stat(tmp_path / "dst")
    assert stat.S_IMODE(dst_st.st_mode) == 0o640
    assert int(dst_st.st_mtime) == 1_000_000


def test_copy_link_metadata_names_the_link_itself(tmp_path, monkeypatch):
    """lchown, not chown: the owner belongs to the link, not to its target.

    A guest can point an entry at a host file, so following the link here would
    hand that file away to whoever the source happens to be owned by.
    """
    (tmp_path / "target").write_text("target data")
    os.symlink("target", tmp_path / "link")
    calls = []
    monkeypatch.setattr(
        os,
        "chown",
        lambda name, uid, gid, dir_fd=None, follow_symlinks=True: calls.append(
            (name, uid, gid, dir_fd, follow_symlinks)
        ),
    )

    src_st = os.lstat(tmp_path / "link")
    with opened(tmp_path) as fd:
        dirfd.copy_link_metadata(fd, "link", src_st)

    assert len(calls) == 1
    name, uid, gid, dir_fd, follow = calls[0]
    assert (name, uid, gid, follow) == ("link", src_st.st_uid, src_st.st_gid, False)
    assert dir_fd is not None


# ── a requested owner ─────────────────────────────────────────────────────────
@contextlib.contextmanager
def recorded_chowns(monkeypatch, root):
    """Record every lchown as a path relative to *root*, performing none of them.

    Handing out real ids would need a second uid to hand them to, so the calls
    are recorded; the dir_fd is read back through /proc so the path a call would
    have landed on is visible, which is the part a symlink could change.
    """
    seen = []

    def record(name, uid, gid, dir_fd=None, follow_symlinks=True):
        base = os.readlink(f"/proc/self/fd/{dir_fd}") if dir_fd is not None else ""
        seen.append((os.path.relpath(os.path.join(base, name), str(root)), uid, gid, follow_symlinks))

    monkeypatch.setattr(os, "chown", record)
    yield seen


def test_copy_metadata_prefers_a_requested_owner_over_the_sources(tmp_path, monkeypatch):
    (tmp_path / "src").write_text("payload")
    (tmp_path / "dst").write_text("")
    calls = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))

    src_st = os.stat(tmp_path / "src")
    sfd = os.open(str(tmp_path / "src"), os.O_RDONLY)
    dfd = os.open(str(tmp_path / "dst"), os.O_WRONLY)
    try:
        dirfd.copy_metadata(sfd, dfd, src_st, owner=(1002, -1))
    finally:
        os.close(dfd)
        os.close(sfd)

    # -1 is chown(2)'s "leave this one alone", so `--chown user` with no group
    # named on a host destination reaches here half-filled and stays that way.
    assert calls == [(1002, -1)]


def test_copy_link_metadata_can_set_an_owner_with_no_times_to_carry(tmp_path, monkeypatch):
    # The move fast path has no source stat to hand over: the entry it renamed
    # already carries its own times, and only the owner is being changed.
    os.symlink("target", tmp_path / "link")
    utimes = []
    monkeypatch.setattr(os, "utime", lambda *a, **kw: utimes.append(a))

    with recorded_chowns(monkeypatch, tmp_path) as seen, opened(tmp_path) as fd:
        dirfd.copy_link_metadata(fd, "link", owner=(7, 9))

    assert seen == [("link", 7, 9, False)]
    assert utimes == []


def test_chown_tree_at_reaches_the_root_and_everything_under_it(tmp_path, monkeypatch):
    _tree(tmp_path / "tree")

    with recorded_chowns(monkeypatch, tmp_path) as seen, opened(tmp_path) as fd:
        dirfd.chown_tree_at(fd, "tree", (7, 9))

    assert {rel for rel, _uid, _gid, _follow in seen} == {
        "tree",
        "tree/a.txt",
        "tree/link",
        "tree/sub",
        "tree/sub/b.txt",
    }
    # lchown throughout: a rename carries symlinks across as symlinks, and
    # following one here would give away whatever the guest aimed it at.
    assert all((uid, gid, follow) == (7, 9, False) for _rel, uid, gid, follow in seen)


def test_chown_tree_at_names_a_symlinked_directory_but_stays_out_of_it(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("not yours")
    tree = tmp_path / "tree"
    tree.mkdir()
    os.symlink(str(outside), tree / "link")

    with recorded_chowns(monkeypatch, tmp_path) as seen, opened(tmp_path) as fd:
        dirfd.chown_tree_at(fd, "tree", (7, 9))

    assert {rel for rel, _uid, _gid, _follow in seen} == {"tree", "tree/link"}


def test_chown_tree_at_reports_a_refusal_and_carries_on(tmp_path, monkeypatch):
    _tree(tmp_path / "tree")
    errors = []

    def refuse(name, uid, gid, dir_fd=None, follow_symlinks=True):
        if name == "a.txt":
            raise OSError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(os, "chown", refuse)
    with opened(tmp_path) as fd:
        dirfd.chown_tree_at(fd, "tree", (7, 9), on_error=lambda rel, exc: errors.append((rel, exc.errno)))

    assert errors == [("a.txt", errno.EPERM)]

    with opened(tmp_path) as fd, pytest.raises(PermissionError):
        dirfd.chown_tree_at(fd, "tree", (7, 9))


def test_chown_tree_at_survives_a_tree_deeper_than_its_fd_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(dirfd, "MAX_OPEN_LEVELS", 2)
    deep = tmp_path / "tree"
    for i in range(12):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / "bottom.txt").write_text("floor")

    with recorded_chowns(monkeypatch, tmp_path) as seen, opened(tmp_path) as fd:
        dirfd.chown_tree_at(fd, "tree", (7, 9))

    bottom = os.path.join("tree", *(f"level{i}" for i in range(12)), "bottom.txt")
    assert bottom in {rel for rel, _uid, _gid, _follow in seen}
