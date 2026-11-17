"""Detached log descriptors and failed starts stay inside runtime storage."""

import contextlib
import errno
import os
import socket
import stat
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import paths
from chroot_distro.commands import login
from chroot_distro.exceptions import ChrootDistroError


@pytest.fixture
def state(tmp_path, monkeypatch):
    runtime = tmp_path / "anchor" / "chroot-distro"
    monkeypatch.setattr(paths, "IS_TERMUX", False)
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    data = runtime / "data" / "box"
    data.mkdir(parents=True)
    return data


def assert_closed(fd):
    with pytest.raises(OSError) as exc:
        os.fstat(fd)
    assert exc.value.errno == errno.EBADF


def test_append_preserves_content_and_all_open_writers(state):
    first = paths.open_container_log("box")
    second = paths.open_container_log("box")
    try:
        assert os.path.samestat(os.fstat(first), os.fstat(second))
        assert stat.S_IMODE(os.fstat(first).st_mode) == 0o600
        os.write(first, b"first\n")
        os.write(second, b"second\n")
        os.write(first, b"third\n")
    finally:
        os.close(first)
        os.close(second)
    assert (state / "run.log").read_bytes() == b"first\nsecond\nthird\n"


def test_existing_log_keeps_its_mode_and_bytes(state):
    entry = state / "run.log"
    entry.write_bytes(b"old\n")
    entry.chmod(0o640)
    fd = paths.open_container_log("box")
    try:
        os.write(fd, b"new\n")
    finally:
        os.close(fd)
    assert entry.read_bytes() == b"old\nnew\n"
    assert stat.S_IMODE(entry.stat().st_mode) == 0o640


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "socket", "device"])
def test_unsafe_log_is_refused_before_open(state, tmp_path, monkeypatch, kind):
    victim = tmp_path / "host"
    victim.write_bytes(b"KEEP")
    victim.chmod(0o600)
    entry = state / "run.log"
    with contextlib.ExitStack() as stack:
        if kind == "symlink":
            entry.symlink_to(victim)
        elif kind == "hardlink":
            os.link(victim, entry)
        elif kind == "fifo":
            os.mkfifo(entry)
        elif kind == "directory":
            entry.mkdir()
        else:
            if kind == "socket":
                sock = stack.enter_context(socket.socket(socket.AF_UNIX))
                info = os.fstat(sock.fileno())
            else:
                info = os.stat(os.devnull)
            real_stat = paths.dirfd.lstat_at
            monkeypatch.setattr(
                paths.dirfd,
                "lstat_at",
                lambda fd, leaf: info if leaf == "run.log" else real_stat(fd, leaf),
            )
        opener = Mock(wraps=paths.dirfd.open_regular_at)
        monkeypatch.setattr(paths.dirfd, "open_regular_at", opener)
        with pytest.raises(OSError):
            paths.open_container_log("box")
        opener.assert_not_called()
    assert victim.read_bytes() == b"KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600


def test_hardlink_removed_after_initial_stat_is_refused(state, tmp_path, monkeypatch):
    victim = tmp_path / "host"
    victim.write_bytes(b"KEEP")
    entry = state / "run.log"
    os.link(victim, entry)
    real_stat = paths.dirfd.lstat_at

    def observe(fd, leaf):
        before = real_stat(fd, leaf)
        entry.unlink()
        assert victim.stat().st_nlink == 1
        return before

    monkeypatch.setattr(paths.dirfd, "lstat_at", observe)
    with pytest.raises(OSError):
        paths.open_container_log("box")
    assert victim.read_bytes() == b"KEEP"


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "regular"])
def test_replaced_log_is_never_handed_off(state, tmp_path, monkeypatch, when, kind):
    victim = tmp_path / "host"
    victim.write_bytes(b"KEEP")
    entry = state / "run.log"
    entry.write_bytes(b"old")
    real_open = paths.dirfd.open_regular_at
    opened_fds = []

    # Keep the original inode allocated so its number cannot be reused.
    def replace():
        entry.rename(state / "old.log")
        if kind == "symlink":
            entry.symlink_to(victim)
        elif kind == "hardlink":
            os.link(victim, entry)
        else:
            entry.write_bytes(b"replacement")

    def opening(fd, leaf, flags, mode):
        if when == "before":
            replace()
        result = real_open(fd, leaf, flags, mode)
        opened_fds.append(result[0])
        if when == "after":
            replace()
        return result

    monkeypatch.setattr(paths.dirfd, "open_regular_at", opening)
    with pytest.raises(OSError):
        paths.open_container_log("box")
    for fd in opened_fds:
        assert_closed(fd)
    assert victim.read_bytes() == b"KEEP"


def test_substituted_host_hardlink_unlinked_before_fstat_is_refused(state, tmp_path, monkeypatch):
    victim = tmp_path / "host"
    victim.write_bytes(b"KEEP")
    entry = state / "run.log"
    entry.write_bytes(b"old")
    real_open = paths.dirfd.open_file_at
    opened_fds = []

    def opening(fd, leaf, flags, mode):
        entry.unlink()
        os.link(victim, entry)
        result = real_open(fd, leaf, flags, mode)
        entry.unlink()
        assert os.fstat(result).st_nlink == 1
        opened_fds.append(result)
        return result

    monkeypatch.setattr(paths.dirfd, "open_file_at", opening)
    with pytest.raises(OSError):
        paths.open_container_log("box")
    assert_closed(opened_fds[0])
    assert victim.read_bytes() == b"KEEP"


@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink"])
def test_create_collision_validates_the_winner(state, tmp_path, monkeypatch, kind):
    entry = state / "run.log"
    victim = tmp_path / "host"
    victim.write_bytes(b"KEEP")
    real_open = paths.dirfd.open_regular_at
    attempts = []

    def opening(fd, leaf, flags, mode):
        attempts.append(flags)
        if len(attempts) == 1:
            if kind == "regular":
                entry.write_bytes(b"peer\n")
            elif kind == "symlink":
                entry.symlink_to(victim)
            else:
                os.link(victim, entry)
        return real_open(fd, leaf, flags, mode)

    monkeypatch.setattr(paths.dirfd, "open_regular_at", opening)
    if kind == "regular":
        fd = paths.open_container_log("box")
        try:
            os.write(fd, b"ours\n")
        finally:
            os.close(fd)
        assert entry.read_bytes() == b"peer\nours\n"
        assert len(attempts) == 2
    else:
        with pytest.raises(OSError):
            paths.open_container_log("box")
        assert len(attempts) == 1
    assert victim.read_bytes() == b"KEEP"


@pytest.mark.parametrize("existing", [False, True])
def test_interrupted_log_validation_closes_file_and_parent(state, monkeypatch, existing):
    if existing:
        (state / "run.log").write_bytes(b"old")
    real_parent = paths.open_container_data_dir
    real_open = paths.dirfd.open_regular_at
    real_stat = paths.dirfd.lstat_at
    descriptors = []

    def parent(name, **kwargs):
        fd = real_parent(name, **kwargs)
        descriptors.append(fd)
        return fd

    def opening(*args, **kwargs):
        result = real_open(*args, **kwargs)
        descriptors.append(result[0])
        return result

    def observe(*args):
        if len(descriptors) == 2:
            raise KeyboardInterrupt
        return real_stat(*args)

    monkeypatch.setattr(paths, "open_container_data_dir", parent)
    monkeypatch.setattr(paths.dirfd, "open_regular_at", opening)
    monkeypatch.setattr(paths.dirfd, "lstat_at", observe)
    with pytest.raises(KeyboardInterrupt):
        paths.open_container_log("box")
    assert len(descriptors) == 2
    for fd in descriptors:
        assert_closed(fd)
    assert (state / "run.log").read_bytes() == (b"old" if existing else b"")


@pytest.mark.parametrize("part", ["runtime", "data", "container"])
def test_log_uses_pinned_parent_after_replacement(state, tmp_path, monkeypatch, part):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "run.log").write_bytes(b"KEEP")
    target = {"runtime": state.parent.parent, "data": state.parent, "container": state}[part]
    saved = tmp_path / "saved"
    relative = state.relative_to(target)
    real_open = paths.open_container_data_dir
    retained = []

    def opening(name, **kwargs):
        fd = real_open(name, **kwargs)
        retained.append(fd)
        target.rename(saved)
        target.symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(paths, "open_container_data_dir", opening)
    fd = paths.open_container_log("box")
    try:
        os.write(fd, b"guest\n")
        assert_closed(retained[0])
    finally:
        os.close(fd)
    assert (saved / relative / "run.log").read_bytes() == b"guest\n"
    assert list(outside.iterdir()) == [outside / "run.log"]
    assert (outside / "run.log").read_bytes() == b"KEEP"


@pytest.mark.parametrize(
    "platform,part",
    [
        (platform, part)
        for platform, parts in (
            ("linux", ("runtime", "data", "container")),
            ("termux", ("runtime", "data", "container", "var", "lib")),
        )
        for part in parts
    ],
)
def test_log_refuses_symlinked_storage_parents(tmp_path, monkeypatch, platform, part):
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    runtime = anchor / ("var/lib/chroot-distro" if platform == "termux" else "chroot-distro")
    monkeypatch.setattr(paths, "IS_TERMUX", platform == "termux")
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    target = {
        "runtime": runtime,
        "data": runtime / "data",
        "container": runtime / "data/box",
        "var": anchor / "var",
        "lib": anchor / "var/lib",
    }[part]
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        paths.open_container_log("box")
    assert list(outside.iterdir()) == []


@pytest.fixture
def detached(state, monkeypatch):
    handle = Mock()
    handle.fileno.return_value = 99
    sweep = Mock(return_value=[])
    unmount = Mock()
    decrement = Mock(return_value=0)
    clear = Mock()
    release = Mock()
    mode = Mock()
    holder = SimpleNamespace(pid=123, _live_ns_flags=Mock(return_value=0))
    monkeypatch.setattr(login, "_reap_session_processes", sweep)
    monkeypatch.setattr(login.session, "lock", lambda name: contextlib.nullcontext(77))
    monkeypatch.setattr(login.session, "decrement", decrement)
    monkeypatch.setattr(login.session, "clear_mount_options", clear)
    monkeypatch.setattr(login.mount_manager, "unmount_all", unmount)
    monkeypatch.setattr(login.namespace, "release_holder", release)
    monkeypatch.setattr(login.namespace, "clear_isolation_mode", mode)
    monkeypatch.setattr(login, "container_rootfs", lambda name: "rootfs")
    config = SimpleNamespace(rootfs="rootfs", command=["sh"], uid=0, gid=0, groups=[], workdir="/")

    def run():
        login._run_detached(
            "box",
            chroot_config=config,
            child_env={"KEY": "value"},
            holder=holder,
            session_handle=handle,
            no_new_privs=True,
        )

    return SimpleNamespace(
        run=run,
        handle=handle,
        sweep=sweep,
        unmount=unmount,
        decrement=decrement,
        clear=clear,
        release=release,
        mode=mode,
        holder=holder,
    )


@pytest.mark.parametrize("failure", ["log", "devnull", "flags", "spawn", "interrupt"])
def test_startup_failures_close_resources_before_shared_teardown(detached, state, monkeypatch, failure):
    opened = []
    real_open = login.open_container_log

    def log_open(name):
        if failure == "log":
            raise OSError("log refused")
        fd = real_open(name)
        opened.append(fd)
        return fd

    monkeypatch.setattr(login, "open_container_log", log_open)
    if failure == "devnull":
        monkeypatch.setattr(login, "open", Mock(side_effect=OSError("devnull failed")), raising=False)
    if failure == "flags":
        detached.holder._live_ns_flags.side_effect = OSError("flags failed")

    def spawn(command, **kwargs):
        opened.append(kwargs["stdin_fd"])
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise OSError("spawn failed")

    monkeypatch.setattr(login, "spawn_detached", spawn)

    def decrement(name, *, state_fd):
        detached.handle.close.assert_called_once_with()
        for fd in opened:
            assert_closed(fd)
        return 0

    detached.decrement.side_effect = decrement
    expected = KeyboardInterrupt if failure == "interrupt" else ChrootDistroError
    with pytest.raises(expected):
        detached.run()
    detached.decrement.assert_called_once_with("box", state_fd=77)
    detached.sweep.assert_called_once_with("box", exclude_pid=123)
    detached.unmount.assert_called_once_with("rootfs", holder=detached.holder)
    detached.clear.assert_called_once_with("box", state_fd=77)
    detached.release.assert_called_once_with("box", state_fd=77)
    detached.mode.assert_called_once_with("box", state_fd=77)


@pytest.mark.parametrize("gate", ["peer", "survivor"])
def test_failed_start_preserves_other_sessions_or_surviving_processes(detached, monkeypatch, gate):
    monkeypatch.setattr(login, "open_container_log", Mock(side_effect=OSError("refused")))
    if gate == "peer":
        detached.decrement.return_value = 1
    else:
        detached.sweep.return_value = [456]
    with pytest.raises(ChrootDistroError):
        detached.run()
    detached.handle.close.assert_called_once_with()
    detached.unmount.assert_not_called()
    detached.clear.assert_not_called()
    detached.release.assert_not_called()
    detached.mode.assert_not_called()
    if gate == "peer":
        detached.sweep.assert_not_called()


@pytest.mark.parametrize("failure", [None, "output", "close"])
def test_successful_spawn_hands_off_log_and_never_tears_down(detached, state, monkeypatch, failure):
    descriptors = []
    child_copy = []

    def spawn(command, **kwargs):
        assert command == ["sh"]
        assert kwargs["env"] == {"KEY": "value"}
        assert kwargs["keep_fds"] == (99,)
        assert kwargs["stdout_fd"] == kwargs["stderr_fd"]
        log_fd = kwargs["stdout_fd"]
        assert os.path.samestat(os.fstat(log_fd), (state / "run.log").stat())
        os.write(log_fd, b"stdout\n")
        os.write(kwargs["stderr_fd"], b"stderr\n")
        assert os.read(kwargs["stdin_fd"], 1) == b""
        descriptors.extend((log_fd, kwargs["stdin_fd"]))
        child_copy.append(os.dup(log_fd))
        return 456

    monkeypatch.setattr(login, "spawn_detached", spawn)
    if failure == "output":
        monkeypatch.setattr("chroot_distro.message.log_info", Mock(side_effect=OSError("output failed")))
    elif failure == "close":
        detached.handle.close.side_effect = OSError("close failed")
    try:
        if failure:
            expected = OSError if failure == "output" else ChrootDistroError
            with pytest.raises(expected):
                detached.run()
        else:
            detached.run()
        for fd in descriptors:
            assert_closed(fd)
        detached.handle.close.assert_called_once_with()
        detached.decrement.assert_not_called()
        detached.unmount.assert_not_called()
        detached.release.assert_not_called()
        os.write(child_copy[0], b"child\n")
        assert (state / "run.log").read_bytes() == b"stdout\nstderr\nchild\n"
    finally:
        for fd in child_copy:
            os.close(fd)


def test_log_success_path_escapes_control_bytes(detached, monkeypatch, capsys):
    monkeypatch.setattr(login, "container_log_path", lambda name: "logs/\x1b[31m\nrun.log")
    monkeypatch.setattr(login, "spawn_detached", Mock(return_value=456))
    detached.run()
    output = capsys.readouterr().err
    assert "logs/\\e[31m\\nrun.log" in output
    assert "\x1b[31m" not in output


def test_real_spawn_uses_validated_log_after_parent_closes_it(state):
    fd = paths.open_container_log("box")
    devnull = os.open(os.devnull, os.O_RDONLY)
    try:
        pid = login.spawn_detached(
            [sys.executable, "-c", "import os; os.write(1,b'out'); os.write(2,b'err')"],
            stdin_fd=devnull,
            stdout_fd=fd,
            stderr_fd=fd,
        )
    finally:
        os.close(fd)
        os.close(devnull)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert (state / "run.log").read_bytes() == b"outerr"
