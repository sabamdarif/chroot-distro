"""Registry publication and pruning stay under the pinned runtime directory."""

import contextlib
import errno
import fcntl
import gc
import json
import os
import select
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import atomic, dirfd, paths
from chroot_distro.helpers import session_registry as registry


@pytest.fixture
def sessions(tmp_path, monkeypatch):
    runtime = tmp_path / "xdg" / "chroot-distro"
    monkeypatch.setattr(paths, "IS_TERMUX", False)
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(paths, "SESSIONS_DIR", str(runtime / "sessions"))
    directory = runtime / "sessions"
    directory.mkdir(parents=True)
    return directory


def register(command=None):
    return registry.register_session(
        container="box", kind="run", command_argv=["sh"] if command is None else command, user="root"
    )


def record_path(sessions):
    return sessions / f"{os.getpid()}.json"


@pytest.mark.parametrize("location", ["temporary", "final"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_planted_entries_cannot_overwrite_host_files(sessions, tmp_path, monkeypatch, location, kind):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    victim.chmod(0o600)
    final = record_path(sessions)
    entry = final
    if location == "temporary":
        entry = sessions / f"{final.name}.{os.getpid()}.{'00' * 8}.tmp"
        random_values = iter((bytes(8), b"\x01" * 8))
        monkeypatch.setattr(atomic.os, "urandom", lambda size: next(random_values))
    if kind == "symlink":
        entry.symlink_to(victim)
    else:
        os.link(victim, entry)
    handle = register()
    assert handle is not None
    try:
        assert registry.active_sessions()[0]["container"] == "box"
        assert stat.S_IMODE(final.stat().st_mode) == 0o644
        assert not final.is_symlink()
        assert victim.read_text() == "KEEP"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600
        if location == "temporary":
            assert os.path.samefile(entry, victim)
    finally:
        handle.close()


@pytest.mark.parametrize(
    "platform,part",
    [
        ("linux", "runtime"),
        ("linux", "sessions"),
        ("termux", "var"),
        ("termux", "lib"),
        ("termux", "runtime"),
        ("termux", "sessions"),
    ],
)
def test_registry_refuses_symlinks_below_platform_anchor(tmp_path, monkeypatch, platform, part):
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    runtime = anchor / ("var/lib/chroot-distro" if platform == "termux" else "chroot-distro")
    monkeypatch.setattr(paths, "IS_TERMUX", platform == "termux")
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(paths, "SESSIONS_DIR", str(runtime / "sessions"))
    target = {"var": anchor / "var", "lib": anchor / "var/lib", "runtime": runtime, "sessions": runtime / "sessions"}[
        part
    ]
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "123.json"
    victim.write_text('{"pid":123}')
    target.symlink_to(outside, target_is_directory=True)
    assert register() is None
    assert registry.active_sessions() == []
    assert list(outside.iterdir()) == [victim]
    assert victim.read_text() == '{"pid":123}'


@pytest.mark.parametrize("termux", [False, True])
def test_registry_allows_an_alias_at_platform_anchor(tmp_path, monkeypatch, termux):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    suffix = "var/lib/chroot-distro" if termux else "chroot-distro"
    monkeypatch.setattr(paths, "IS_TERMUX", termux)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(alias))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(alias / suffix))
    monkeypatch.setattr(paths, "SESSIONS_DIR", str(alias / suffix / "sessions"))
    handle = register()
    assert handle is not None
    try:
        final = record_path(actual / suffix / "sessions")
        assert stat.S_IMODE(final.stat().st_mode) == 0o644
        assert registry.active_sessions()[0]["container"] == "box"
    finally:
        handle.close()


@pytest.mark.parametrize("failure", [None, OSError, KeyboardInterrupt])
@pytest.mark.parametrize("parent", ["runtime", "sessions"])
def test_publication_and_cleanup_keep_parent_pin(sessions, tmp_path, monkeypatch, parent, failure):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = sessions if parent == "sessions" else sessions.parent
    moved = tmp_path / "moved"
    relative = sessions.relative_to(target)
    real_replace = os.replace

    def replace(src, dst, **kwargs):
        target.rename(moved)
        target.symlink_to(outside, target_is_directory=True)
        (outside / src).write_text("KEEP TEMP")
        (outside / dst).write_text("KEEP FINAL")
        if failure is not None:
            raise failure("publication failed")
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(atomic.os, "replace", replace)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            register()
        handle = None
    else:
        handle = register()
    try:
        assert (handle is not None) == (failure is None)
        pinned = moved / relative
        assert not list(pinned.glob("*.tmp"))
        assert record_path(pinned).exists() == (failure is None)
        assert sorted(p.read_text() for p in outside.iterdir()) == ["KEEP FINAL", "KEEP TEMP"]
    finally:
        if handle is not None:
            handle.close()


def test_staging_substitution_does_not_publish_or_chmod_host_file(sessions, tmp_path, monkeypatch):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    victim.chmod(0o600)
    real_fsync = os.fsync

    def fsync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            (temporary,) = sessions.glob("*.tmp")
            temporary.unlink()
            temporary.symlink_to(victim)
        real_fsync(fd)

    monkeypatch.setattr(atomic.os, "fsync", fsync)
    assert register() is None
    assert not record_path(sessions).exists()
    assert not list(sessions.iterdir())
    assert victim.read_text() == "KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor inventory")
@pytest.mark.parametrize("operation", ["dup", "fdopen", "set_inheritable", "replace", "fsync"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_publication_closes_all_descriptors(sessions, monkeypatch, operation, error):
    before = set(os.listdir("/proc/self/fd"))
    original = getattr(os, operation)

    def fail(*args, **kwargs):
        if operation == "dup" and stat.S_ISDIR(os.fstat(args[0]).st_mode):
            return original(*args, **kwargs)
        raise error("injected failure")

    with monkeypatch.context() as patcher:
        patcher.setattr(os, operation, fail)
        if error is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                register()
        else:
            assert register() is None
    assert not list(sessions.glob("*.tmp"))
    assert registry.active_sessions() == []
    assert set(os.listdir("/proc/self/fd")) == before


def test_handle_close_is_idempotent_and_drop_releases_lock(sessions):
    handle = register()
    assert handle is not None
    handle.close()
    handle.close()
    with pytest.raises(ValueError, match="closed"):
        handle.fileno()
    assert registry.active_sessions() == []
    handle = register()
    assert handle is not None
    fd = handle.fileno()
    del handle
    gc.collect()
    with pytest.raises(OSError) as exc:
        os.fstat(fd)
    assert exc.value.errno == errno.EBADF
    assert registry.active_sessions() == []


@pytest.mark.skipif(sys.platform != "linux", reason="requires inherited flock across exec")
def test_session_lock_survives_exec_and_parent_handle_close(sessions):
    handle = register()
    assert handle is not None
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    child = None
    try:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os,sys; os.write(int(sys.argv[1]),b'K'); os.read(int(sys.argv[2]),1)",
                str(ready_w),
                str(release_r),
            ],
            pass_fds=(handle.fileno(), ready_w, release_r),
        )
        os.close(ready_w)
        os.close(release_r)
        assert select.select([ready_r], [], [], 5)[0]
        assert os.read(ready_r, 1) == b"K"
        handle.close()
        assert registry.active_sessions()[0]["pid"] == os.getpid()
        os.write(release_w, b"X")
        assert child.wait(timeout=5) == 0
        assert registry.active_sessions() == []
    finally:
        handle.close()
        for fd in (ready_r, ready_w, release_r, release_w):
            with contextlib.suppress(OSError):
                os.close(fd)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_detached_spawn_failure_preserves_error_after_repeated_close(sessions, monkeypatch, capsys):
    from chroot_distro.commands import login

    handle = register()
    assert handle is not None
    unmount = Mock()
    monkeypatch.setattr(login, "container_log_path", lambda name: str(sessions.parent / "run.log"))
    monkeypatch.setattr(login, "container_rootfs", lambda name: "rootfs")
    monkeypatch.setattr(login, "spawn_detached", Mock(side_effect=OSError("fork failed")))
    monkeypatch.setattr(
        login,
        "session",
        SimpleNamespace(
            lock=lambda name: contextlib.nullcontext(None),
            decrement=lambda *args, **kwargs: 0,
            clear_mount_options=Mock(),
        ),
    )
    monkeypatch.setattr(login, "mount_manager", SimpleNamespace(unmount_all=unmount))
    try:
        with pytest.raises(SystemExit) as exc:
            login._run_detached(
                "box", chroot_config=SimpleNamespace(command=["sh"]), child_env={}, holder=None, session_handle=handle
            )
        assert exc.value.code == 1
        assert "fork failed" in capsys.readouterr().err
        unmount.assert_called_once_with("rootfs", holder=None)
        assert registry.active_sessions() == []
    finally:
        handle.close()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_reader_refuses_nonregular_entries(sessions, tmp_path, kind):
    victim = tmp_path / "host"
    victim.write_text('{"pid":123}')
    entry = sessions / "123.json"
    if kind == "symlink":
        entry.symlink_to(victim)
    elif kind == "fifo":
        os.mkfifo(entry)
    else:
        entry.mkdir()
    assert registry.active_sessions() == []
    assert entry.lstat()
    assert victim.read_text() == '{"pid":123}'


@pytest.mark.parametrize("error", [errno.EIO, errno.EBADF, errno.ENOLCK])
def test_unexpected_flock_error_does_not_prove_liveness_or_prune(sessions, monkeypatch, error):
    entry = record_path(sessions)
    entry.write_text('{"pid":123}')
    monkeypatch.setattr(fcntl, "flock", Mock(side_effect=OSError(error, "flock failed")))
    assert registry.active_sessions() == []
    assert entry.read_text() == '{"pid":123}'


def test_reader_and_lock_probe_use_same_inode(sessions, monkeypatch):
    handle = register()
    assert handle is not None
    final = record_path(sessions)
    real_flock = fcntl.flock

    def flock(fd, operation):
        final.rename(sessions / "old")
        final.write_text('{"container":"replacement"}')
        return real_flock(fd, operation)

    monkeypatch.setattr(fcntl, "flock", flock)
    try:
        assert registry.active_sessions()[0]["container"] == "box"
        assert json.loads(final.read_text())["container"] == "replacement"
    finally:
        handle.close()


def test_pruning_keeps_directory_pin_after_parent_swap(sessions, tmp_path, monkeypatch):
    final = record_path(sessions)
    final.write_text('{"pid":123}')
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / final.name
    victim.write_text("KEEP")
    moved = tmp_path / "moved"
    real_listdir = os.listdir

    def listdir(fd):
        sessions.rename(moved)
        sessions.symlink_to(outside, target_is_directory=True)
        return real_listdir(fd)

    monkeypatch.setattr(registry.os, "listdir", listdir)
    assert registry.active_sessions() == []
    assert not (moved / final.name).exists()
    assert victim.read_text() == "KEEP"


def test_pruning_refuses_entry_substituted_before_identity_check(sessions, monkeypatch):
    final = record_path(sessions)
    final.write_text('{"pid":123}')
    real_lstat = dirfd.lstat_at

    def lstat(directory_fd, name):
        final.rename(sessions / "old")
        final.write_text("KEEP REPLACEMENT")
        return real_lstat(directory_fd, name)

    monkeypatch.setattr(dirfd, "lstat_at", lstat)
    assert registry.active_sessions() == []
    assert final.read_text() == "KEEP REPLACEMENT"


@pytest.mark.parametrize("payload", [b"x" * (1024 * 1024 + 1), b"[" * 20000 + b"0" + b"]" * 20000, b"\xff", b"{bad"])
def test_locked_invalid_record_is_skipped_without_pruning(sessions, payload):
    entry = record_path(sessions)
    entry.write_bytes(payload)
    with entry.open("rb") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert registry.active_sessions() == []
        assert entry.read_bytes() == payload


def test_writer_and_reader_share_exact_ascii_size_limit(sessions, monkeypatch):
    monkeypatch.setattr(registry.time, "time", lambda: 1.0)
    handle = register(["\u2603"])
    assert handle is not None
    try:
        baseline = record_path(sessions).read_bytes()
        assert b"\\u2603" in baseline
        assert baseline.endswith(b"\n")
    finally:
        handle.close()
    command = "\u2603" + "x" * (registry._RECORD_LIMIT - len(baseline))
    handle = register([command])
    assert handle is not None
    try:
        assert record_path(sessions).stat().st_size == registry._RECORD_LIMIT
        assert registry.active_sessions()[0]["command"] == [command]
        assert register([command + "x"]) is None
        assert registry.active_sessions()[0]["command"] == [command]
    finally:
        handle.close()


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="requires descriptor inventory")
@pytest.mark.parametrize("operation", ["listdir", "loads"])
def test_reader_interrupt_closes_descriptors_without_releasing_holder(sessions, monkeypatch, operation):
    handle = register()
    assert handle is not None
    before = set(os.listdir("/proc/self/fd"))
    try:
        with monkeypatch.context() as patcher:
            target = registry.os if operation == "listdir" else registry.json
            patcher.setattr(target, operation, Mock(side_effect=KeyboardInterrupt))
            with pytest.raises(KeyboardInterrupt):
                registry.active_sessions()
        assert set(os.listdir("/proc/self/fd")) == before
        assert registry.active_sessions()[0]["container"] == "box"
    finally:
        handle.close()
