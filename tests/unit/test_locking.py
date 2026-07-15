import os
from unittest.mock import patch

import pytest

from chroot_distro.exceptions import LockConflictError
from chroot_distro.locking import (
    BuildLock,
    ContainerLock,
    _held_exclusive,
    _pid_state,
    container_lock_path,
    read_lock_info,
)


def test_container_lock_path():
    path = container_lock_path("alpine")
    assert path.endswith("locks/alpine.lock")


def test_lock_info_dead_pid(tmp_path):
    lock_file = tmp_path / "dead.lock"
    # Write a dead PID
    lock_file.write_text("999999 mycommand\n")
    info = read_lock_info(str(lock_file))
    assert info == ""


def test_lock_info_valid_pid(tmp_path):
    lock_file = tmp_path / "valid.lock"
    pid = os.getpid()
    lock_file.write_text(f"{pid} mycmd\n")
    info = read_lock_info(str(lock_file))
    assert f"PID {pid}: mycmd" in info


def test_lock_info_empty_or_missing(tmp_path):
    assert read_lock_info(str(tmp_path / "missing.lock")) == ""
    empty_file = tmp_path / "empty.lock"
    empty_file.write_text("")
    assert read_lock_info(str(empty_file)) == ""


def test_lock_info_stopped_pid(tmp_path):
    """A suspended (Ctrl+Z'd) holder is called out with resume/kill hints."""
    lock_file = tmp_path / "stopped.lock"
    pid = os.getpid()
    lock_file.write_text(f"{pid} install\n")
    with patch("chroot_distro.locking._pid_state", return_value="T"):
        info = read_lock_info(str(lock_file))
    assert f"PID {pid}: install" in info
    assert "suspended" in info
    assert f"kill -CONT {pid}" in info
    assert f"kill {pid}" in info


def test_pid_state_self_running():
    # Our own process is running (R) or sleeping (S) — never stopped.
    assert _pid_state(os.getpid()) in ("R", "S")


def test_pid_state_dead_pid():
    assert _pid_state(999999999) == ""


def test_failed_acquire_preserves_holder_info(tmp_path):
    """A conflicting acquire must NOT truncate the holder's PID line.

    The old code opened the lock file with mode "w" (truncating) *before*
    attempting the flock, so every conflict wiped the diagnostics and the
    error degraded to a bare "container 'x' is busy." with no PID hint.
    """
    lock_path = tmp_path / "busy.lock"
    pid = os.getpid()

    with patch("chroot_distro.locking.container_lock_path", return_value=str(lock_path)):
        _held_exclusive.clear()

        holder = ContainerLock("busy", exclusive=True, command="install")
        assert holder.acquire() is True
        assert f"{pid} install" in lock_path.read_text()

        # Simulate a second process: bypass the re-entrancy fast path.
        with patch("chroot_distro.locking._held_exclusive", set()):
            contender = ContainerLock("busy", exclusive=True, command="install")
            assert contender.acquire() is False

        # The holder's diagnostic line must have survived the conflict...
        assert f"{pid} install" in lock_path.read_text()
        # ...so the conflict error can actually name the busy process.
        with (
            patch("chroot_distro.locking._held_exclusive", set()),
            pytest.raises(LockConflictError, match=rf"PID {pid}: install"),
            ContainerLock("busy", exclusive=True, command="install"),
        ):
            pass

        holder.release()


def test_acquire_truncates_stale_content(tmp_path):
    """A successful acquire replaces any stale line from a dead holder."""
    lock_path = tmp_path / "stale.lock"
    lock_path.write_text("999999 old-command-that-died\n")

    with patch("chroot_distro.locking.container_lock_path", return_value=str(lock_path)):
        _held_exclusive.clear()
        lock = ContainerLock("stale", exclusive=True, command="remove")
        assert lock.acquire() is True
        content = lock_path.read_text()
        assert content == f"{os.getpid()} remove\n"
        lock.release()


def test_container_lock_lifecycle(tmp_path):
    lock_path = tmp_path / "my_container.lock"

    with patch("chroot_distro.locking.container_lock_path", return_value=str(lock_path)):
        # Clear held exclusive set to ensure isolation
        _held_exclusive.clear()

        # Shared lock can be acquired
        lock1 = ContainerLock("my_container", exclusive=False, command="login")
        assert lock1.acquire() is True
        assert str(lock_path) not in _held_exclusive

        # Another shared lock can be acquired simultaneously
        lock2 = ContainerLock("my_container", exclusive=False, command="run")
        assert lock2.acquire() is True

        # Exclusive lock cannot be acquired while shared locks are active
        lock3 = ContainerLock("my_container", exclusive=True, command="remove")
        assert lock3.acquire() is False

        # Release shared locks
        lock1.release()
        lock2.release()

        # Now exclusive lock can be acquired
        assert lock3.acquire() is True
        assert str(lock_path) in _held_exclusive

        # Another lock (shared or exclusive) cannot be acquired now
        lock4 = ContainerLock("my_container", exclusive=False, command="login")
        with patch("chroot_distro.locking._held_exclusive", set()):
            assert lock4.acquire() is False

        lock5 = ContainerLock("my_container", exclusive=True, command="remove")
        # However, exclusive re-entrancy is supported:
        assert lock5.acquire() is True
        assert lock5._reentrant is True

        # Context manager test
        with (
            pytest.raises(LockConflictError),
            patch("chroot_distro.locking._held_exclusive", set()),
            ContainerLock("my_container", exclusive=True, command="remove"),
        ):
            pass

        lock3.release()
        assert str(lock_path) not in _held_exclusive


def test_build_lock(tmp_path):
    with patch("chroot_distro.locking._BUILD_LOCKS_DIR", str(tmp_path)):
        _held_exclusive.clear()
        lock1 = BuildLock("myrepo/myapp:1.0", "aarch64", command="build")
        assert lock1.acquire() is True

        # BuildLock is exclusive, so another cannot acquire it
        lock2 = BuildLock("myrepo/myapp:1.0", "aarch64", command="build")
        with patch("chroot_distro.locking._held_exclusive", set()):
            assert lock2.acquire() is False

        lock1.release()
        assert lock2.acquire() is True
        lock2.release()


def test_locking_oserror_warnings(tmp_path):
    lock_path = tmp_path / "denied/my_container.lock"
    lock = ContainerLock("my_container", exclusive=True, command="login")
    lock._lock_path = str(lock_path)

    # 1. os.makedirs fails
    def mock_makedirs(*args, **kwargs):
        raise OSError("Permission denied")

    with patch("os.makedirs", mock_makedirs), patch("logging.Logger.warning") as mock_warn:
        assert lock.acquire() is True
        mock_warn.assert_called_once()
        assert "Could not create lock directory" in mock_warn.call_args[0][0]

    # 2. open fails
    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    with patch("os.makedirs", lambda *a, **k: None), patch("builtins.open", mock_open), patch("logging.Logger.warning") as mock_warn:
        assert lock.acquire() is True
        mock_warn.assert_called_once()
        assert "Could not open/create lock file" in mock_warn.call_args[0][0]
