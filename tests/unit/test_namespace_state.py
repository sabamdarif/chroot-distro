"""Holder records stay beneath one pinned runtime directory."""

import errno
import os
import signal
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro import paths
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.helpers import isolation
from chroot_distro.helpers import namespace as ns
from chroot_distro.syscalls._constants import CLONE_NEWNS, CLONE_NEWPID


READERS = {
    "holder.pid": ns._read_holder_pid,
    "holder.flags": ns._read_holder_flags,
    "holder.maxiso": ns.holder_is_max_isolation,
    "isolation.mode": ns.read_isolation_mode,
}


@pytest.fixture
def state(tmp_path, monkeypatch):
    runtime = tmp_path / "anchor/chroot-distro"
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(paths, "IS_TERMUX", False)
    directory = runtime / "data/box"
    directory.mkdir(parents=True)
    return directory


@pytest.fixture
def spawned(monkeypatch):
    spawn = Mock(return_value=(4321, 4320))
    monkeypatch.setattr(ns, "_spawn_holder", spawn)
    monkeypatch.setattr(ns, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ns, "_get_process_start_time", lambda pid: 12.0)
    monkeypatch.setattr(ns, "filter_accessible_namespaces", lambda pid, flags: flags)
    monkeypatch.setattr(ns.os, "kill", Mock())
    monkeypatch.setattr(ns.os, "waitpid", Mock(return_value=(4320, 0)))
    return spawn


def plant(entry, victim, kind):
    if kind == "symlink":
        entry.symlink_to(victim)
    else:
        os.link(victim, entry)


@pytest.mark.parametrize("name", READERS)
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_reads_refuse_unsafe_entries(state, tmp_path, name, kind):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    entry = state / name
    if kind == "fifo":
        os.mkfifo(entry)
    elif kind == "directory":
        entry.mkdir()
    else:
        plant(entry, victim, kind)
    with pytest.raises(ChrootDistroError) as exc:
        READERS[name]("box")
    assert not isinstance(exc.value, ns.NamespaceError)
    assert victim.read_text() == "KEEP"
    assert entry.lstat()


@pytest.mark.parametrize("name", READERS)
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_publication_replaces_links(state, tmp_path, spawned, name, kind):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    if name == "isolation.mode":
        plant(state / name, victim, kind)
        ns.write_isolation_mode("box", ns.ISOLATION_MODE_NAMESPACE)
    else:
        def spawn(*args, **kwargs):
            plant(state / name, victim, kind)
            return 4321, 4320

        spawned.side_effect = spawn
        ns._create_holder("box", CLONE_NEWNS, rootfs="unused")
    assert victim.read_text() == "KEEP"
    assert not (state / name).is_symlink()
    assert not os.path.samestat(victim.stat(), (state / name).stat())
    assert stat.S_IMODE((state / name).stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_cleanup_unlinks_entries_without_touching_targets(state, tmp_path, kind):
    victim = tmp_path / "host"
    victim.write_text("KEEP")
    for name in READERS:
        plant(state / name, victim, kind)
    ns._remove_holder_state("box")
    ns.clear_isolation_mode("box")
    assert not list(state.iterdir())
    assert victim.read_text() == "KEEP"


@pytest.mark.parametrize("payload", [b"\xff", b"x" * 4097])
def test_malformed_records_are_bounded(state, payload):
    for name in READERS:
        (state / name).write_bytes(payload)
    assert ns._read_holder_pid("box") is None
    assert ns._read_holder_flags("box") == CLONE_NEWNS
    assert ns.read_isolation_mode("box") is None
    assert not ns.holder_is_max_isolation("box")


def test_read_size_boundary_and_legacy_records(state, monkeypatch):
    (state / "isolation.mode").write_text(" " * (4096 - 4) + "host")
    assert ns.read_isolation_mode("box") == "host"
    (state / "holder.flags").write_text("--mount --pid")
    assert ns._read_holder_flags("box") == CLONE_NEWNS | CLONE_NEWPID
    (state / "holder.pid").write_text("4321\n12.0\ncustom\n")
    monkeypatch.setattr(ns, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(ns, "_get_process_start_time", lambda pid: 12.0)
    assert ns._read_holder_pid("box") == 4321
    (state / "holder.maxiso").write_text("1")
    assert ns.holder_is_max_isolation("box")


def test_missing_state_lookup_and_cleanup_do_not_create_directories(state):
    for reader in READERS.values():
        reader("missing")
    assert ns.get_live_holder("missing") is None
    ns.release_holder("missing")
    ns._remove_holder_state("missing")
    ns.clear_isolation_mode("missing")
    assert sorted(p.name for p in state.parent.iterdir()) == ["box"]


@pytest.mark.parametrize("termux,part", [
    (False, "runtime"), (False, "data"), (False, "container"),
    (True, "var"), (True, "lib"), (True, "runtime"), (True, "data"), (True, "container"),
])
def test_directory_walk_refuses_planted_parents(state, tmp_path, monkeypatch, termux, part):
    anchor = tmp_path / "platform"
    anchor.mkdir()
    runtime = anchor / ("var/lib/chroot-distro" if termux else "chroot-distro")
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(runtime))
    monkeypatch.setattr(paths, "IS_TERMUX", termux)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(anchor))
    target = {
        "var": anchor / "var", "lib": anchor / "var/lib", "runtime": runtime,
        "data": runtime / "data", "container": runtime / "data/box",
    }[part]
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "isolation.mode").write_text("KEEP")
    target.symlink_to(outside, target_is_directory=True)
    for operation in (
        lambda: ns.write_isolation_mode("box", "namespace"),
        lambda: ns.read_isolation_mode("box"),
        lambda: ns.clear_isolation_mode("box"),
        lambda: ns._remove_holder_state("box"),
    ):
        with pytest.raises(ChrootDistroError):
            operation()
    assert [p.name for p in outside.iterdir()] == ["isolation.mode"]
    assert (outside / "isolation.mode").read_text() == "KEEP"


@pytest.mark.parametrize("termux", [False, True])
def test_platform_anchor_alias_remains_supported(state, tmp_path, monkeypatch, termux):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    suffix = "var/lib/chroot-distro" if termux else "chroot-distro"
    monkeypatch.setattr(paths, "IS_TERMUX", termux)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(alias))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(alias / suffix))
    ns.write_isolation_mode("box", "host")
    assert (actual / suffix / "data/box/isolation.mode").read_text() == "host"


@pytest.mark.parametrize("part", ["runtime", "data", "container"])
def test_borrowed_pin_survives_parent_swap(state, tmp_path, part):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "isolation.mode").write_text("KEEP")
    target = {"runtime": state.parent.parent, "data": state.parent, "container": state}[part]
    saved = tmp_path / "saved"
    with ns._state_dir("box") as fd:
        target.rename(saved)
        target.symlink_to(outside, target_is_directory=True)
        ns.write_isolation_mode("box", "host", state_fd=fd)
        ns._write_holder_flags("box", CLONE_NEWNS, state_fd=fd)
        assert ns.read_isolation_mode("box", state_fd=fd) == "host"
        assert ns._read_holder_flags("box", state_fd=fd) == CLONE_NEWNS
        ns._remove_holder_state("box", state_fd=fd)
        ns.clear_isolation_mode("box", state_fd=fd)
        assert not os.listdir(fd)
    assert (outside / "isolation.mode").read_text() == "KEEP"


@pytest.mark.parametrize("record", ["holder.pid", "holder.flags", "holder.maxiso"])
@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_failed_publication_kills_and_reaps_new_holder(state, spawned, monkeypatch, record, failure_type):
    original = ns.os.replace
    failure = failure_type(errno.EIO, "publication failed")

    def replace(src, dest, **kwargs):
        if dest == record:
            raise failure
        return original(src, dest, **kwargs)

    monkeypatch.setattr(ns.os, "replace", replace)
    expected = ChrootDistroError if failure_type is OSError else KeyboardInterrupt
    with pytest.raises(expected) as exc:
        ns._create_holder("box", CLONE_NEWNS, rootfs="unused")
    if failure_type is OSError:
        assert exc.value.__cause__ is failure
        assert not isinstance(exc.value, ns.NamespaceError)
    else:
        assert exc.value is failure
    ns.os.kill.assert_called_once_with(4321, signal.SIGKILL)
    ns.os.waitpid.assert_called_once_with(4320, 0)
    assert not list(state.iterdir())


def test_stale_lookup_never_deletes_concurrent_publication(state, monkeypatch):
    (state / "holder.pid").write_text("4321\n12.0\n")

    def alive(pid):
        (state / "holder.pid").write_text("5555\n13.0\n")
        (state / "holder.flags").write_text("0x00020000")
        return False

    monkeypatch.setattr(ns, "_pid_alive", alive)
    assert ns.get_live_holder("box") is None
    assert (state / "holder.pid").read_text() == "5555\n13.0\n"
    assert (state / "holder.flags").read_text() == "0x00020000"


@pytest.mark.parametrize("wrapper", [isolation.namespace_session, isolation.max_isolation_session])
def test_build_lifecycle_keeps_pin_across_directory_replacement(state, tmp_path, spawned, monkeypatch, wrapper):
    original_finalize = isolation.finalize_holder
    saved = tmp_path / "saved"
    killed = []
    alive = True

    def kill(pid, sig):
        nonlocal alive
        killed.append((pid, sig))
        alive = False

    def finalize(holder, key, **kwargs):
        state.rename(saved)
        state.mkdir()
        (state / "holder.pid").write_text("unrelated")
        (state / "isolation.mode").write_text("KEEP")
        original_finalize(holder, key, **kwargs)

    monkeypatch.setattr(ns, "_pid_alive", lambda pid: alive)
    monkeypatch.setattr(ns.os, "kill", kill)
    monkeypatch.setattr(ns, "probe_unshare_flags", lambda: CLONE_NEWNS)
    monkeypatch.setattr(isolation, "probe_isolation", lambda: SimpleNamespace(missing_mandatory=False, has_userns=False))
    monkeypatch.setattr(isolation, "finalize_holder", finalize)
    monkeypatch.setattr(ns, "make_mount_private", lambda holder: True)
    monkeypatch.setattr(isolation, "write_resolv_conf", lambda root: None)
    monkeypatch.setattr(isolation, "apply_special_mounts", lambda *args, **kwargs: None)
    monkeypatch.setattr(isolation.mount_manager, "unmount_all", lambda *args, **kwargs: None)
    monkeypatch.setattr("chroot_distro.commands.login.bindings.get_bindings", lambda **kwargs: ([], []))
    with wrapper("box", str(tmp_path / "rootfs")) as holder:
        assert holder.pid == 4321
        assert (saved / "isolation.mode").read_text() == "namespace"
    assert killed == [(4321, signal.SIGTERM)]
    assert not list(saved.iterdir())
    assert (state / "holder.pid").read_text() == "unrelated"
    assert (state / "isolation.mode").read_text() == "KEEP"


@pytest.mark.parametrize("wrapper", [isolation.namespace_session, isolation.max_isolation_session])
def test_build_state_error_never_falls_back(state, monkeypatch, wrapper):
    error = ChrootDistroError("unsafe state")
    holder = SimpleNamespace(pid=4321)
    monkeypatch.setattr(isolation, "probe_isolation", lambda: SimpleNamespace(missing_mandatory=False, has_userns=False))
    monkeypatch.setattr(ns, "acquire_holder", Mock(return_value=holder))
    monkeypatch.setattr(isolation, "finalize_holder", Mock(side_effect=error))
    teardown = Mock()
    monkeypatch.setattr(isolation, "_teardown", teardown)
    with pytest.raises(ChrootDistroError) as exc:
        with wrapper("box", "unused"):
            pytest.fail("storage failure fell back to an unisolated build")
    assert exc.value is error
    teardown.assert_called_once()
