"""Session state I/O stays under the pinned runtime directory."""

import errno
import fcntl
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from chroot_distro import paths
from chroot_distro.exceptions import ChrootDistroError, InvalidNameError
from chroot_distro.helpers import session


@pytest.fixture
def state(tmp_path, monkeypatch):
    runtime = tmp_path / "xdg" / "chroot-distro"
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(paths, "IS_TERMUX", False)
    monkeypatch.setattr(session, "get_active_chroot_pids", lambda name: [123])
    data = runtime / "data" / "box"
    data.mkdir(parents=True)
    return data


def plant_link(entry, victim, kind):
    if kind == "symlink":
        entry.symlink_to(victim)
    else:
        os.link(victim, entry)


def test_lock_refuses_symlink_without_truncating(state, tmp_path):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    plant_link(state / "sessions.lock", victim, "symlink")
    with pytest.raises(ChrootDistroError, match="session state"):
        with session.lock("box"):
            pytest.fail("planted lock acquired")
    assert victim.read_text() == "KEEP"
    assert (state / "sessions.lock").is_symlink()


def test_lock_preserves_hardlinked_inode_and_exclusion(state, tmp_path):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    entry = state / "sessions.lock"
    plant_link(entry, victim, "hardlink")
    original = entry.stat()
    with session.lock("box") as state_fd:
        assert os.path.samestat(os.fstat(state_fd), state.stat())
        with entry.open("r+") as peer:
            with pytest.raises(BlockingIOError):
                fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert session.increment("box", state_fd=state_fd) == 1
    with entry.open("r+") as peer:
        fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert victim.read_text() == "KEEP"
    assert os.path.samestat(original, entry.stat())


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_lock_refuses_other_types_without_removing_them(state, kind):
    entry = state / "sessions.lock"
    if kind == "fifo":
        os.mkfifo(entry)
    else:
        entry.mkdir()
    original = entry.lstat()
    with pytest.raises(ChrootDistroError):
        with session.lock("box"):
            pytest.fail("non-regular lock acquired")
    assert os.path.samestat(original, entry.lstat())


@pytest.mark.parametrize("operation", ["increment", "decrement", "count", "reset"])
def test_counter_update_replaces_hardlink(state, tmp_path, monkeypatch, operation):
    victim = tmp_path / "host"
    victim.write_text("7")
    os.link(victim, state / "sessions")
    if operation == "count":
        monkeypatch.setattr(session, "get_active_chroot_pids", lambda name: [])
    result = getattr(session, operation)("box")
    expected = {"increment": 8, "decrement": 6, "count": 0, "reset": None}[operation]
    assert result == expected
    assert (state / "sessions").read_text() == str(expected if expected is not None else 0)
    assert victim.read_text() == "7"
    assert not os.path.samestat(victim.stat(), (state / "sessions").stat())


@pytest.mark.parametrize("operation", ["increment", "decrement", "count"])
def test_counter_read_refuses_symlink(state, tmp_path, operation):
    victim = tmp_path / "host"
    victim.write_text("7")
    (state / "sessions").symlink_to(victim)
    with pytest.raises(ChrootDistroError):
        getattr(session, operation)("box")
    assert victim.read_text() == "7"


def test_reset_replaces_counter_symlink(state, tmp_path):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    (state / "sessions").symlink_to(victim)
    session.reset("box")
    assert (state / "sessions").read_text() == "0"
    assert not (state / "sessions").is_symlink()
    assert victim.read_text() == "KEEP"


def test_removed_hardlink_before_fstat_is_never_written_through(state, tmp_path, monkeypatch):
    victim = tmp_path / "host"
    victim.write_text("7")
    entry = state / "sessions"
    os.link(victim, entry)
    real_fstat = session.dirfd.os.fstat

    def fstat(fd):
        info = real_fstat(fd)
        if os.path.samestat(info, victim.stat()) and entry.exists():
            entry.unlink()
            return real_fstat(fd)
        return info

    monkeypatch.setattr(session.dirfd.os, "fstat", fstat)
    assert session.increment("box") == 8
    assert victim.read_text() == "7"
    assert entry.read_text() == "8"


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("operation", ["save", "clear"])
def test_mount_options_never_write_through_links(state, tmp_path, kind, operation):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    entry = state / "mount_opts.json"
    plant_link(entry, victim, kind)
    if operation == "save":
        session.save_mount_options("box", {"shared_home": True})
        assert not entry.is_symlink()
        assert json.loads(entry.read_text()) == {"shared_home": True}
    else:
        session.clear_mount_options("box")
        assert not entry.exists()
    assert victim.read_text() == "KEEP"


@pytest.mark.parametrize("part", ["runtime", "data", "container"])
def test_operations_keep_the_lock_directory_pin_after_parent_swap(state, tmp_path, part):
    (state / "sessions").write_text("1")
    session.save_mount_options("box", {"old": True})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sessions").write_text("70")
    (outside / "mount_opts.json").write_text('{"host":true}')
    target = {"runtime": state.parent.parent, "data": state.parent, "container": state}[part]
    saved = tmp_path / "saved"
    relative = state.relative_to(target)
    with session.lock("box") as state_fd:
        target.rename(saved)
        target.symlink_to(outside, target_is_directory=True)
        assert session.increment("box", state_fd=state_fd) == 2
        assert session.load_mount_options("box", state_fd=state_fd) == {"old": True}
        session.save_mount_options("box", {"new": True}, state_fd=state_fd)
        assert session.load_mount_options("box", state_fd=state_fd) == {"new": True}
        assert session.decrement("box", state_fd=state_fd) == 1
        session.clear_mount_options("box", state_fd=state_fd)
    assert (saved / relative / "sessions").read_text() == "1"
    assert not (saved / relative / "mount_opts.json").exists()
    assert (outside / "sessions").read_text() == "70"
    assert (outside / "mount_opts.json").read_text() == '{"host":true}'


@pytest.mark.parametrize("platform,part", [("linux", "runtime"), ("linux", "data"), ("linux", "container"), ("termux", "var"), ("termux", "lib"), ("termux", "runtime"), ("termux", "data"), ("termux", "container")])
def test_state_walk_refuses_links_below_platform_anchor(state, tmp_path, monkeypatch, platform, part):
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    runtime = anchor / ("var/lib/chroot-distro" if platform == "termux" else "chroot-distro")
    monkeypatch.setattr(paths, "IS_TERMUX", platform == "termux")
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    target = {"var": anchor / "var", "lib": anchor / "var/lib", "runtime": runtime, "data": runtime / "data", "container": runtime / "data/box"}[part]
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mount_opts.json").write_text("KEEP")
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ChrootDistroError):
        session.increment("box")
    session.save_mount_options("box", {"shared_home": True})
    assert session.load_mount_options("box") is None
    session.clear_mount_options("box")
    assert [p.name for p in outside.iterdir()] == ["mount_opts.json"]
    assert (outside / "mount_opts.json").read_text() == "KEEP"


@pytest.mark.parametrize("termux", [False, True])
def test_alias_at_platform_anchor_is_allowed(state, tmp_path, monkeypatch, termux):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    suffix = "var/lib/chroot-distro" if termux else "chroot-distro"
    monkeypatch.setattr(paths, "IS_TERMUX", termux)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(alias))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(alias / suffix))
    assert session.increment("box") == 1
    assert (actual / suffix / "data/box/sessions").read_text() == "1"


@pytest.mark.parametrize("name", ["../outside", "", "a/b", "\u00b2"])
def test_state_directory_validates_names(state, name):
    with pytest.raises(InvalidNameError):
        session.reset(name)


@pytest.mark.parametrize("payload", [b"", b"bad", b"-5", b"9" * 65])
def test_malformed_counters_restart_at_one(state, payload):
    (state / "sessions").write_bytes(payload)
    assert session.increment("box") == 1
    assert session.decrement("box") == 0
    assert session.decrement("box") == 0


def test_stale_increment_clears_options_using_same_pin(state, monkeypatch):
    (state / "sessions").write_text("9")
    session.save_mount_options("box", {"shared_home": True})
    real_clear = session.clear_mount_options
    cleared = []

    def clear(name, *, state_fd=None):
        assert state_fd is not None
        cleared.append(state_fd)
        real_clear(name, state_fd=state_fd)

    monkeypatch.setattr(session, "get_active_chroot_pids", lambda name: [])
    monkeypatch.setattr(session, "clear_mount_options", clear)
    assert session.increment("box") == 1
    assert len(cleared) == 1
    assert not (state / "mount_opts.json").exists()
    assert session.decrement("box") == 0


def test_concurrent_session_updates_do_not_lose_joins(state):
    def update(operation):
        for _ in range(12):
            operation("box")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(update, [session.increment] * 4))
    assert session.count("box") == 48
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(update, [session.decrement] * 4))
    assert session.count("box") == 0


@pytest.mark.parametrize("payload", [b"[]", b"null", b"{", b"\xff", b"[" * 2000 + b"]" * 2000, b" " * (1024 * 1024 + 1)])
def test_malformed_mount_options_are_ignored(state, payload):
    (state / "mount_opts.json").write_bytes(payload)
    assert session.load_mount_options("box") is None


def test_options_size_limit_matches_writer_and_reader(state, monkeypatch):
    monkeypatch.setattr(session, "_MOUNT_OPTIONS_LIMIT", 32)
    opts = {"v": "x" * 23}
    assert len(json.dumps(opts)) == 32
    session.save_mount_options("box", opts)
    assert session.load_mount_options("box") == opts
    session.save_mount_options("box", {"v": "x" * 24})
    assert session.load_mount_options("box") == opts


def test_fifo_reads_do_not_block(state):
    os.mkfifo(state / "sessions")
    os.mkfifo(state / "mount_opts.json")
    with pytest.raises(ChrootDistroError):
        session.count("box")
    assert session.load_mount_options("box") is None


def test_mount_options_read_refuses_final_symlink(state, tmp_path):
    victim = tmp_path / "host"
    victim.write_text('{"shared_home":true}')
    (state / "mount_opts.json").symlink_to(victim)
    assert session.load_mount_options("box") is None
    assert victim.read_text() == '{"shared_home":true}'


@pytest.mark.parametrize("target", ["sessions", "mount_opts.json"])
def test_failed_publication_preserves_previous_state(state, monkeypatch, target):
    entry = state / target
    before = "4" if target == "sessions" else '{"shared_home":true}'
    entry.write_text(before)

    def replace(*args, **kwargs):
        raise OSError(errno.EIO, "publication failed")

    monkeypatch.setattr(session.os, "replace", replace)
    if target == "sessions":
        with pytest.raises(ChrootDistroError, match="publication failed"):
            session.increment("box")
    else:
        session.save_mount_options("box", {"shared_home": False})
    assert entry.read_text() == before
    assert not list(state.glob("*.tmp"))


def test_interrupted_counter_publication_preserves_previous_state(state, monkeypatch):
    (state / "sessions").write_text("4")

    def replace(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(session.os, "replace", replace)
    with pytest.raises(KeyboardInterrupt):
        session.increment("box")
    assert (state / "sessions").read_text() == "4"
    assert sorted(p.name for p in state.iterdir()) == ["sessions", "sessions.lock"]
    with session.lock("box"):
        pass


def test_lock_failure_closes_directory_and_lock_descriptors(state, monkeypatch):
    real_open = session.dirfd.open_regular_at
    opened = []

    def open_regular(fd, name, *args):
        result = real_open(fd, name, *args)
        opened.extend([fd, result[0]])
        return result

    def flock(*args):
        raise OSError(errno.ENOLCK, "no locks")

    monkeypatch.setattr(session.dirfd, "open_regular_at", open_regular)
    monkeypatch.setattr(session.fcntl, "flock", flock)
    with pytest.raises(ChrootDistroError, match="no locks"):
        with session.lock("box"):
            pytest.fail("lock failure was ignored")
    assert len(opened) == 2
    for fd in opened:
        with pytest.raises(OSError) as exc:
            os.fstat(fd)
        assert exc.value.errno == errno.EBADF


def test_lock_does_not_relabel_caller_oserror(state):
    failure = OSError(errno.EIO, "mount failure")
    with pytest.raises(OSError) as exc:
        with session.lock("box"):
            raise failure
    assert exc.value is failure


def test_new_state_files_are_private(state):
    session.increment("box")
    session.save_mount_options("box", {"env": ["VALUE=one"]})
    for name in ("sessions", "sessions.lock", "mount_opts.json"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600
