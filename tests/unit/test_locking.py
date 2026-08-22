import errno
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

from chroot_distro import locking
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


def test_container_lock_path():
    assert container_lock_path("alpine").endswith("locks/alpine.lock")


def test_lock_info_dead_pid(lock_tree):
    _write_lock(lock_tree, "dead.lock", "999999 mycommand\n")
    assert _hint("dead.lock") == ""


def test_lock_info_valid_pid(lock_tree):
    pid = os.getpid()
    _write_lock(lock_tree, "valid.lock", f"{pid} mycmd\n")
    assert f"PID {pid}: mycmd" in _hint("valid.lock")


def test_lock_info_empty_or_missing(lock_tree):
    assert _hint("missing.lock") == ""
    _write_lock(lock_tree, "empty.lock", "")
    assert _hint("empty.lock") == ""


def test_lock_info_stopped_pid(lock_tree):
    """A suspended (Ctrl+Z'd) holder is called out with resume/kill hints."""
    pid = os.getpid()
    _write_lock(lock_tree, "stopped.lock", f"{pid} install\n")
    with patch("chroot_distro.locking._pid_state", return_value="T"):
        info = _hint("stopped.lock")
    assert f"PID {pid}: install" in info
    assert "suspended" in info
    assert f"kill -CONT {pid}" in info


def test_lock_info_ignores_a_planted_symlink(lock_tree, tmp_path):
    # A hint is read out of a guest-writable directory; following a link there
    # would report a host file's first line as this program's own bookkeeping.
    outside = tmp_path / "outside.txt"
    outside.write_text(f"{os.getpid()} not-a-lock\n")
    lock_tree.mkdir(parents=True, exist_ok=True)
    os.symlink(str(outside), str(lock_tree / "linked.lock"))

    assert _hint("linked.lock") == ""


def test_pid_state_self_running():
    # Our own process is running (R) or sleeping (S) — never stopped.
    assert _pid_state(os.getpid()) in ("R", "S")


def test_pid_state_dead_pid():
    assert _pid_state(999999999) == ""


def test_failed_acquire_preserves_holder_info(lock_tree):
    """A conflicting acquire must NOT truncate the holder's PID line.

    Opening the lock file truncating *before* attempting the flock wiped the
    diagnostics on every conflict, and the error degraded to a bare
    "container 'x' is busy." with no PID hint.
    """
    pid = os.getpid()
    holder = ContainerLock("busy", exclusive=True, command="install")
    assert holder.acquire() is True
    lock_path = lock_tree / "busy.lock"
    assert f"{pid} install" in lock_path.read_text()

    # Simulate a second process: bypass the re-entrancy fast path.
    with patch("chroot_distro.locking._held_exclusive", set()):
        contender = ContainerLock("busy", exclusive=True, command="install")
        assert contender.acquire() is False

    assert f"{pid} install" in lock_path.read_text()
    with (
        patch("chroot_distro.locking._held_exclusive", set()),
        pytest.raises(LockConflictError, match=rf"PID {pid}: install"),
        ContainerLock("busy", exclusive=True, command="install"),
    ):
        pass

    holder.release()


def test_acquire_truncates_stale_content(lock_tree):
    """A successful acquire replaces any stale line from a dead holder."""
    _write_lock(lock_tree, "stale.lock", "999999 old-command-that-died\n")

    lock = ContainerLock("stale", exclusive=True, command="remove")
    assert lock.acquire() is True
    assert (lock_tree / "stale.lock").read_text() == f"{os.getpid()} remove\n"
    lock.release()


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


# ── what may be standing under the lock file's name ───────────────────────────
#
# RUNTIME_DIR/locks is guest-writable on Termux -- it sits under the
# $TERMUX_PREFIX bound read-write into every non-isolated container -- and the
# names in it come from the container name, so they are entirely predictable.

def test_a_planted_symlink_is_replaced_not_followed(lock_tree, tmp_path):
    outside = tmp_path / "host-file"
    outside.write_text("KEEP")
    lock_tree.mkdir(parents=True, exist_ok=True)
    os.symlink(str(outside), str(lock_tree / "box.lock"))

    lock = ContainerLock("box", exclusive=True, command="install")
    assert lock.acquire() is True
    lock.release()

    assert outside.read_text() == "KEEP"
    made = lock_tree / "box.lock"
    assert not made.is_symlink()
    assert made.read_text() == f"{os.getpid()} install\n"


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
    assert completed.stdout.strip() == "True", completed.stderr
    assert lock.acquire() is True
    lock.release()
    assert not os.path.islink(str(lock_tree / "box.lock"))


def test_a_name_that_cannot_be_cleared_fails_closed(lock_tree):
    # Proceeding unlocked is right for a filesystem that cannot hold a lock
    # file; being *prevented* from taking one must not pass for that, or
    # planting a directory would run every later command unsynchronised.
    lock_tree.mkdir(parents=True, exist_ok=True)
    planted = lock_tree / "box.lock"
    planted.mkdir()
    (planted / "occupant").write_text("x")

    lock = ContainerLock("box", exclusive=True, command="install")
    assert lock.acquire() is False
    with pytest.raises(LockConflictError, match="not a plain file"):
        with ContainerLock("box", exclusive=True, command="install"):
            pass


def test_an_empty_planted_directory_is_removed(lock_tree):
    lock_tree.mkdir(parents=True, exist_ok=True)
    (lock_tree / "box.lock").mkdir()

    lock = ContainerLock("box", exclusive=True, command="install")
    assert lock.acquire() is True
    lock.release()
    assert (lock_tree / "box.lock").is_file()


def test_a_planted_locks_directory_symlink_is_replaced(lock_tree, tmp_path):
    # A planted level gets what a planted lock file gets: it is dropped and the
    # real directory made in its place, so the lock lands under RUNTIME_DIR and
    # nothing is written where the link pointed.
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(lock_tree))

    lock = ContainerLock("box", exclusive=True, command="install")
    assert lock.acquire() is True
    lock.release()

    assert os.listdir(str(outside)) == []
    assert not os.path.islink(str(lock_tree))
    assert (lock_tree / "box.lock").is_file()


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


def test_drop_planted_reports_a_directory_it_cannot_remove(lock_tree):
    lock_tree.mkdir(parents=True, exist_ok=True)
    (lock_tree / "full").mkdir()
    (lock_tree / "full" / "child").write_text("")
    dir_fd = os.open(str(lock_tree), os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert locking._drop_planted(dir_fd, "full") is False
        assert locking._drop_planted(dir_fd, "gone") is True
    finally:
        os.close(dir_fd)


def test_is_planted_covers_every_type_the_open_reports():
    assert locking._is_planted(OSError(errno.ELOOP, "symlink"))
    assert locking._is_planted(OSError(errno.EISDIR, "directory"))
    assert locking._is_planted(OSError(errno.EINVAL, "not a regular file"))
    assert locking._is_planted(OSError(errno.ENXIO, "fifo"))
    assert not locking._is_planted(OSError(errno.EACCES, "permission denied"))
    assert not locking._is_planted(OSError(errno.EROFS, "read-only"))
