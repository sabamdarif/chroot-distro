import errno
import fcntl
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

from chroot_distro import dirfd, locking
from chroot_distro.exceptions import LockConflictError
from chroot_distro.locking import (
    BuildLock,
    ContainerLock,
    _held_exclusive,
    _pid_state,
    container_lock_path,
)


@pytest.fixture(autouse=True)
def lock_tree(tmp_path, monkeypatch):
    """Redirect the whole lock tree under tmp_path.

    The lock files are reached by walking down from RUNTIME_DIR rather than by
    their path, so a test that only redirects the path would have acquire()
    write into the real state directory.
    """
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    locks = runtime / "locks"
    monkeypatch.setattr(locking, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(locking, "LOCKS_DIR", str(locks))
    monkeypatch.setattr(locking, "_BUILD_LOCKS_DIR", str(locks / "build"))
    monkeypatch.setattr(locking, "_RUN_CACHE_LOCKS_DIR", str(locks / "run-cache"))
    _held_exclusive.clear()
    yield locks
    _held_exclusive.clear()


def _hint(name):
    return locking._hint_for(locking._CONTAINER_PARTS, name)


def _write_lock(lock_tree, name, text):
    lock_tree.mkdir(parents=True, exist_ok=True)
    path = lock_tree / name
    path.write_text(text)
    return path


def _record(pid, command):
    return f"chroot-distro-lock-v1 {pid} {command}\n"


def test_container_lock_path():
    assert container_lock_path("alpine").endswith("locks/alpine.lock")


@pytest.mark.parametrize("length", [250, 251, 255])
def test_container_lock_at_name_limit(lock_tree, length):
    name = "x" * length
    with ContainerLock(name, exclusive=True, command="install") as holder:
        basename = os.path.basename(holder.lock_path)
        assert len(os.fsencode(basename)) <= dirfd.NAME_MAX
        if length == 250:
            assert basename == f"{name}.lock"
        assert os.path.isfile(holder.lock_path)
        assert locking.container_busy_status(name) == f"in use (PID {os.getpid()}: install)"
        assert [path for path, _ in locking.busy_locks()] == [holder.lock_path]

        with patch.object(locking, "_held_exclusive", set()):
            contender = ContainerLock(name, exclusive=True, command="remove")
            assert not contender.acquire()
            assert contender.holder_hint() == f" (PID {os.getpid()}: install)"
            if length > 250:
                with ContainerLock(name[:-1] + "y", exclusive=True, command="install") as other:
                    assert other.lock_path != holder.lock_path
                    assert os.path.isfile(other.lock_path)


def test_overlong_lock_filename_fails_acquisition(lock_tree, caplog):
    lock_tree.mkdir()
    lock = ContainerLock("box", exclusive=True, command="install")
    too_long = OSError(errno.ENAMETOOLONG, "File name too long")
    with patch.object(dirfd, "open_regular_at", side_effect=too_long) as open_lock:
        assert not lock.acquire()
        open_lock.assert_called_once()
    assert "filename is too long for the filesystem" in caplog.text
    assert "Proceeding unlocked" not in caplog.text

    fd = dirfd.opendir(str(lock_tree))
    try:
        with patch.object(dirfd, "open_regular_at", side_effect=too_long) as open_lock:
            assert locking.open_lock_file_at(fd, "box.lock", lock.lock_path) is None
            open_lock.assert_called_once()
    finally:
        os.close(fd)


def test_lock_info_dead_pid(lock_tree):
    _write_lock(lock_tree, "dead.info", _record(999999, "install"))
    with patch.object(os, "kill", side_effect=ProcessLookupError(errno.ESRCH, "missing process")):
        assert _hint("dead.lock") == ""


def test_lock_info_valid_pid(lock_tree):
    pid = os.getpid()
    _write_lock(lock_tree, "valid.info", _record(pid, "install"))
    assert _hint("valid.lock") == f" (PID {pid}: install)"


def test_lock_info_for_pid_without_signal_permission(lock_tree):
    pid = os.getpid()
    _write_lock(lock_tree, "valid.info", _record(pid, "install"))
    with patch.object(os, "kill", side_effect=PermissionError(errno.EPERM, "not permitted")) as kill:
        assert _hint("valid.lock") == f" (PID {pid}: install)"
    kill.assert_called_once_with(pid, 0)


@pytest.mark.parametrize(
    "record",
    [
        _record(0, "install"),
        _record(-1, "install"),
        _record(2147483648, "install"),
        _record("²", "install"),
        _record(1, "install\x1b[2J"),
        _record(1, "x" * 200),
        "chroot-distro-lock-v1 1 install",
        "1 install\n",
    ],
)
def test_lock_info_rejects_invalid_records(lock_tree, record):
    _write_lock(lock_tree, "box.info", record)
    with patch.object(os, "kill") as kill:
        assert _hint("box.lock") == ""
    kill.assert_not_called()


def test_lock_info_empty_or_missing(lock_tree):
    assert _hint("missing.lock") == ""
    _write_lock(lock_tree, "empty.info", "")
    assert _hint("empty.lock") == ""


def test_lock_info_stopped_pid(lock_tree):
    pid = os.getpid()
    _write_lock(lock_tree, "stopped.info", _record(pid, "install"))
    with patch("chroot_distro.locking._pid_state", return_value="T"):
        info = _hint("stopped.lock")
    assert info == f" (PID {pid}: install, suspended)"


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_lock_info_neither_reads_nor_overwrites_planted_link_targets(lock_tree, tmp_path, kind):
    outside = tmp_path / "outside.txt"
    original = _record(os.getpid(), "remove")
    outside.write_text(original)
    lock_tree.mkdir(parents=True, exist_ok=True)
    info = lock_tree / "linked.info"
    if kind == "symlink":
        info.symlink_to(outside)
    else:
        info.hardlink_to(outside)

    assert _hint("linked.lock") == ""
    with ContainerLock("linked", exclusive=True, command="install") as lock:
        assert lock.holder_hint() == f" (PID {os.getpid()}: install)"
    assert not info.is_symlink()
    assert outside.read_text() == original


def test_pid_state_self_running():
    # Our own process is running (R) or sleeping (S), never stopped.
    assert _pid_state(os.getpid()) in ("R", "S")


def test_pid_state_dead_pid():
    assert _pid_state(999999999) == ""


def test_failed_acquire_preserves_holder_info(lock_tree):
    pid = os.getpid()
    with ContainerLock("busy", exclusive=True, command="install", inheritable=True) as holder:
        assert os.get_inheritable(holder._fd)
        with ContainerLock("busy", exclusive=True, command="remove"):
            assert holder.holder_hint() == f" (PID {pid}: install)"
        with (
            patch.object(locking, "_held_exclusive", set()),
            pytest.raises(LockConflictError, match=rf"PID {pid}: install"),
            ContainerLock("busy", exclusive=True, command="remove"),
        ):
            pass
        assert (lock_tree / "busy.info").read_text() == _record(pid, "install")


def test_acquire_shares_legacy_lock_without_reading_or_rewriting_it(lock_tree):
    legacy = f"{os.getpid()} install\n"
    path = _write_lock(lock_tree, "stale.lock", legacy)
    with path.open("r+") as peer:
        fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert locking.busy_locks() == [(str(path), "")]
        assert not ContainerLock("stale", exclusive=True, command="remove").acquire()

    with ContainerLock("stale", exclusive=True, command="remove") as lock:
        assert lock.holder_hint() == f" (PID {os.getpid()}: remove)"
    assert path.read_text() == legacy


def test_container_lock_lifecycle(lock_tree):
    lock_path = lock_tree / "my_container.lock"

    lock1 = ContainerLock("my_container", exclusive=False, command="login")
    assert lock1.acquire() is True
    assert str(lock_path) not in _held_exclusive

    lock2 = ContainerLock("my_container", exclusive=False, command="run")
    assert lock2.acquire() is True

    # Exclusive lock cannot be acquired while shared locks are active.
    lock3 = ContainerLock("my_container", exclusive=True, command="remove")
    assert lock3.acquire() is False

    lock1.release()
    lock2.release()

    assert lock3.acquire() is True
    assert str(lock_path) in _held_exclusive

    lock4 = ContainerLock("my_container", exclusive=False, command="login")
    with patch("chroot_distro.locking._held_exclusive", set()):
        assert lock4.acquire() is False

    # Exclusive re-entrancy within one process is supported.
    lock5 = ContainerLock("my_container", exclusive=True, command="remove")
    assert lock5.acquire() is True
    assert lock5._reentrant is True

    with (
        pytest.raises(LockConflictError),
        patch("chroot_distro.locking._held_exclusive", set()),
        ContainerLock("my_container", exclusive=True, command="remove"),
    ):
        pass

    lock3.release()
    assert str(lock_path) not in _held_exclusive


def test_build_lock(lock_tree):
    lock1 = BuildLock("myrepo/myapp:1.0", "aarch64", command="build")
    assert lock1.acquire() is True
    assert os.path.dirname(lock1.lock_path) == str(lock_tree / "build")

    lock2 = BuildLock("myrepo/myapp:1.0", "aarch64", command="build")
    with patch("chroot_distro.locking._held_exclusive", set()):
        assert lock2.acquire() is False

    lock1.release()
    assert lock2.acquire() is True
    lock2.release()


def test_locking_oserror_warnings(lock_tree):
    lock = ContainerLock("my_container", exclusive=True, command="login")

    with patch("os.makedirs", side_effect=OSError("Permission denied")), patch("logging.Logger.warning") as warn:
        assert lock.acquire() is True
        assert "Could not create lock directory" in warn.call_args[0][0]

    with (
        patch("chroot_distro.locking._open_lock_file", return_value=None),
        patch("logging.Logger.warning") as warn,
    ):
        assert lock.acquire() is True
        assert "Could not open/create lock file" in warn.call_args[0][0]


@pytest.mark.parametrize("unlink_after_open", [False, True])
def test_lock_acquisition_keeps_hard_link_target_intact(lock_tree, tmp_path, monkeypatch, unlink_after_open):
    victim = tmp_path / "host-file"
    victim.write_text("KEEP")
    lock_tree.mkdir()
    planted = lock_tree / "box.lock"
    planted.hardlink_to(victim)
    open_file = dirfd.open_file_at

    def open_then_unlink(dir_fd, name, flags, mode=0o644):
        fd = open_file(dir_fd, name, flags, mode)
        if unlink_after_open and name == planted.name:
            planted.unlink()
            assert os.fstat(fd).st_nlink == 1
        return fd

    monkeypatch.setattr(dirfd, "open_file_at", open_then_unlink)
    with ContainerLock("box", exclusive=True, command="install"):
        assert victim.read_text() == "KEEP"


@pytest.mark.parametrize("failure", ["collision", "short write", "rename", "interrupt"])
def test_holder_publication_failure_cleans_up_without_corrupting_locks(lock_tree, monkeypatch, failure):
    lock_tree.mkdir()
    temp = lock_tree / ".holder-0000000000000000.tmp"
    if failure == "collision":
        temp.write_text("KEEP")
        monkeypatch.setattr(os, "urandom", bytes)
    elif failure == "short write":
        monkeypatch.setattr(os, "write", lambda _fd, data: len(data) - 1)
    else:
        error = KeyboardInterrupt if failure == "interrupt" else OSError(errno.EACCES, "denied")

        def fail_replace(*args, **kwargs):
            raise error

        monkeypatch.setattr(os, "replace", fail_replace)

    lock = ContainerLock("box", exclusive=True)
    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            lock.acquire()
        with open(lock.lock_path, "r+") as peer:
            fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert lock.lock_path not in _held_exclusive
    else:
        with lock, open(lock.lock_path, "r+") as peer, pytest.raises(BlockingIOError):
            fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)

    assert not (lock_tree / "box.info").exists()
    assert list(lock_tree.glob("*.tmp")) == ([temp] if failure == "collision" else [])
    if failure == "collision":
        assert temp.read_text() == "KEEP"


# ── what may be standing under the lock file's name ───────────────────────────
#
# RUNTIME_DIR/locks is guest-writable on Termux -- it sits under the
# $TERMUX_PREFIX bound read-write into every non-isolated container -- and the
# names in it come from the container name, so they are entirely predictable.


def test_a_planted_symlink_is_refused(lock_tree, tmp_path):
    outside = tmp_path / "host-file"
    outside.write_text("KEEP")
    lock_tree.mkdir(parents=True, exist_ok=True)
    os.symlink(str(outside), str(lock_tree / "box.lock"))

    lock = ContainerLock("box", exclusive=True, command="install")
    with pytest.raises(LockConflictError, match="unexpected entry.*Stop other chroot-distro commands"):
        with lock:
            pass

    assert outside.read_text() == "KEEP"
    assert (lock_tree / "box.lock").is_symlink()


def test_a_planted_fifo_does_not_stall_the_command(lock_tree):
    # O_NOFOLLOW says nothing about a FIFO, and opening one for writing waits
    # for a reader a hostile guest never supplies.
    lock_tree.mkdir(parents=True, exist_ok=True)
    os.mkfifo(str(lock_tree / "box.lock"))

    lock = ContainerLock("box", exclusive=True, command="install")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, sys;"
            "sys.path.insert(0, 'src');"
            "from chroot_distro import locking;"
            f"locking.RUNTIME_DIR = {str(lock_tree.parent)!r};"
            "lock = locking.ContainerLock('box', exclusive=True, command='install');"
            "print(lock.acquire())",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.stdout.strip() == "False", completed.stderr
    assert not lock.acquire()
    assert (lock_tree / "box.lock").is_fifo()


def test_a_nonempty_directory_at_a_lock_path_is_refused(lock_tree):
    # Proceeding unlocked is right for a filesystem that cannot hold a lock
    # file; being *prevented* from taking one must not pass for that, or
    # planting a directory would run every later command unsynchronised.
    lock_tree.mkdir(parents=True, exist_ok=True)
    planted = lock_tree / "box.lock"
    planted.mkdir()
    (planted / "occupant").write_text("x")

    lock = ContainerLock("box", exclusive=True, command="install")
    assert lock.acquire() is False
    with pytest.raises(LockConflictError, match="unexpected entry"):
        with ContainerLock("box", exclusive=True, command="install"):
            pass


def test_an_empty_directory_at_a_lock_path_is_refused(lock_tree):
    lock_tree.mkdir(parents=True, exist_ok=True)
    (lock_tree / "box.lock").mkdir()

    lock = ContainerLock("box", exclusive=True, command="install")
    assert not lock.acquire()
    assert (lock_tree / "box.lock").is_dir()


def test_a_planted_locks_directory_symlink_is_refused(lock_tree, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(lock_tree))

    lock = ContainerLock("box", exclusive=True, command="install")
    assert not lock.acquire()

    assert os.listdir(str(outside)) == []
    assert lock_tree.is_symlink()


def test_busy_locks_ignores_an_entry_that_is_not_a_plain_file(lock_tree, tmp_path):
    outside = tmp_path / "host-file"
    outside.write_text("")
    lock_tree.mkdir(parents=True, exist_ok=True)
    os.symlink(str(outside), str(lock_tree / "linked.lock"))
    (lock_tree / "dir.lock").mkdir()

    holder = ContainerLock("real", exclusive=True, command="install")
    assert holder.acquire() is True
    try:
        with patch("chroot_distro.locking._held_exclusive", set()):
            held = locking.busy_locks()
    finally:
        holder.release()

    assert [os.path.basename(path) for path, _hint in held] == ["real.lock"]


def test_refusal_preserves_peer_lock_after_a_stale_open_error(lock_tree, monkeypatch):
    lock_tree.mkdir()
    path = lock_tree / "box.lock"
    real_open = dirfd.open_regular_at
    with path.open("w+") as peer:
        fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def report_stale_error(dir_fd, name, *args):
            if name == path.name:
                monkeypatch.setattr(dirfd, "open_regular_at", real_open)
                raise OSError(errno.ELOOP, "observed a symlink")
            return real_open(dir_fd, name, *args)

        monkeypatch.setattr(dirfd, "open_regular_at", report_stale_error)
        assert not ContainerLock("box", exclusive=True).acquire()
        assert os.path.samestat(path.stat(), os.fstat(peer.fileno()))
        assert not ContainerLock("box", exclusive=True).acquire()


def test_refusal_preserves_a_peers_empty_lock_directory(lock_tree, monkeypatch):
    lock_tree.mkdir()
    peer_fd = dirfd.opendir(str(lock_tree))
    real_open = dirfd.opendir_at

    def report_stale_error(dir_fd, name):
        if name == "locks":
            monkeypatch.setattr(dirfd, "opendir_at", real_open)
            raise OSError(errno.ENOTDIR, "observed a symlink")
        return real_open(dir_fd, name)

    monkeypatch.setattr(dirfd, "opendir_at", report_stale_error)
    try:
        assert not ContainerLock("box", exclusive=True).acquire()
        assert os.path.samestat(lock_tree.stat(), os.fstat(peer_fd))
    finally:
        os.close(peer_fd)


def test_ambiguous_open_error_on_nonregular_entry_fails_closed(lock_tree):
    lock_tree.mkdir()
    os.mkfifo(lock_tree / "box.lock")
    with patch.object(dirfd, "open_regular_at", side_effect=PermissionError(errno.EACCES, "denied")):
        assert not ContainerLock("box", exclusive=True).acquire()
