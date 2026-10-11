import os
import signal
import time
from unittest.mock import patch

import pytest

from chroot_distro.syscalls import unshare
from chroot_distro.syscalls._constants import CLONE_NEWNS


# ── probe_namespace_support: aggregates supported bits from child exit codes ──────
def test_probe_namespace_support_reports_supported():
    # Fork returns a fake child pid; waitpid reports exit 0 (supported).
    with (
        patch("os.fork", return_value=1234),
        patch("os.waitpid", return_value=(1234, 0)),
        patch("os.WIFEXITED", return_value=True),
        patch("os.WEXITSTATUS", return_value=0),
    ):
        supported = unshare.probe_namespace_support(CLONE_NEWNS)
    assert supported == CLONE_NEWNS


def test_probe_namespace_support_reports_unsupported():
    with (
        patch("os.fork", return_value=1234),
        patch("os.waitpid", return_value=(1234, 256)),
        patch("os.WIFEXITED", return_value=True),
        patch("os.WEXITSTATUS", return_value=1),
    ):
        supported = unshare.probe_namespace_support(CLONE_NEWNS)
    assert supported == 0


# ── _default_id_map: identity map to caller uid/gid ───────────────────────────────
def test_default_id_map():
    uid_map, gid_map = unshare._default_id_map()
    assert uid_map == f"0 {os.getuid()} 1\n"
    assert gid_map == f"0 {os.getgid()} 1\n"


# ── _write_id_mappings: unprivileged writes setgroups deny then uid/gid ───────────
def test_write_id_mappings_unprivileged(tmp_path, monkeypatch):
    writes = {}

    class FakeFile:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def write(self, data):
            writes[self.name] = data

    def fake_open(path, mode="r", *a, **k):
        return FakeFile(path)

    monkeypatch.setattr(unshare.os, "getuid", lambda: 1000)
    with patch("builtins.open", side_effect=fake_open):
        unshare._write_id_mappings(999, ("0 100000 65536\n", "0 100000 65536\n"))

    assert writes["/proc/999/setgroups"] == "deny"
    assert writes["/proc/999/uid_map"] == "0 100000 65536\n"
    assert writes["/proc/999/gid_map"] == "0 100000 65536\n"


def test_write_id_mappings_privileged_skips_setgroups(monkeypatch):
    writes = {}

    class FakeFile:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def write(self, data):
            writes[self.name] = data

    monkeypatch.setattr(unshare.os, "getuid", lambda: 0)
    with patch("builtins.open", side_effect=lambda p, *a, **k: FakeFile(p)):
        unshare._write_id_mappings(999, ("0 0 1\n", "0 0 1\n"))

    # Root parent leaves setgroups at allow (never written).
    assert "/proc/999/setgroups" not in writes
    assert writes["/proc/999/uid_map"] == "0 0 1\n"


# ── the sleeping holder as PID 1: reap and exit on SIGTERM ────────────────────────
def test_reap_children_drains_zombie():
    # A child that exits and is never waited for stays as a zombie until the
    # SIGCHLD handler drains it.
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    # Wait for the child to die without reaping it.
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                state = fh.read().split()[2]
            if state == "Z":
                break
        except OSError:
            break
        time.sleep(0.01)
    unshare._reap_children()
    # A reaped pid leaves /proc entirely.
    with pytest.raises(FileNotFoundError):
        os.stat(f"/proc/{pid}/stat")


def test_reap_children_without_children_returns():
    unshare._reap_children()  # ChildProcessError path: must not raise


def test_holder_installs_reaping_and_exits_on_sigterm():
    # The parked holder must die on SIGTERM (a bare PID 1 ignores it).
    pid = os.fork()
    if pid == 0:
        unshare._install_holder_signals()
        try:
            while True:
                time.sleep(2147483647)
        except BaseException:
            pass
        os._exit(0)

    time.sleep(0.2)
    os.kill(pid, signal.SIGTERM)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0


# ── Tier B: the idmap handshake between parent and holder ────────────────────────
def test_stack_idmapped_rootfs_mounts_on_confirmation(monkeypatch):
    calls = {}
    monkeypatch.setattr(unshare.os, "read", lambda fd, n: b"I")
    monkeypatch.setattr(unshare.os, "close", lambda fd: calls.setdefault("closed", []).append(fd))
    import chroot_distro.syscalls.idmap as idmap

    monkeypatch.setattr(idmap, "move_mount", lambda *a, **k: calls.setdefault("move", a))
    monkeypatch.setattr(unshare.log, "error", lambda *a, **k: calls.setdefault("logged", a))
    unshare._stack_idmapped_rootfs(7, 8, "/tmp/rootfs")
    assert calls["move"] == (8, "", -100, "/tmp/rootfs", idmap.MOVE_MOUNT_F_EMPTY_PATH)
    assert 7 in calls["closed"] and 8 in calls["closed"]
    assert "logged" not in calls


def test_stack_idmapped_rootfs_eof_exits(monkeypatch):
    # os._exit(1) would take the test runner with it, so it raises here instead.
    monkeypatch.setattr(unshare.os, "read", lambda fd, n: b"")
    monkeypatch.setattr(unshare.os, "close", lambda fd: None)
    monkeypatch.setattr(unshare.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    import chroot_distro.syscalls.idmap as idmap

    monkeypatch.setattr(idmap, "move_mount", lambda *a, **k: pytest.fail("must not mount"))
    with pytest.raises(SystemExit):
        unshare._stack_idmapped_rootfs(7, 8, "/tmp/rootfs")


def test_stack_idmapped_rootfs_mount_failure_exits(monkeypatch):
    monkeypatch.setattr(unshare.os, "read", lambda fd, n: b"I")
    monkeypatch.setattr(unshare.os, "close", lambda fd: None)
    monkeypatch.setattr(unshare.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    import chroot_distro.syscalls.idmap as idmap

    def boom(*a, **k):
        raise OSError(22, "invalid")

    monkeypatch.setattr(idmap, "move_mount", boom)
    monkeypatch.setattr(unshare.log, "exception", lambda *a, **k: None)
    monkeypatch.setattr(unshare.log, "error", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        unshare._stack_idmapped_rootfs(7, 8, "/tmp/rootfs")


def test_apply_idmap_to_clone_sets_idmap(monkeypatch):
    import chroot_distro.syscalls.idmap as idmap

    seen = {}
    monkeypatch.setattr(unshare.os, "open", lambda p, f: 33)
    monkeypatch.setattr(unshare.os, "close", lambda fd: seen.setdefault("close", []).append(fd))
    monkeypatch.setattr(
        idmap, "mount_setattr", lambda fd, path, flags, attr: seen.update(fd=fd, path=path, flags=flags, attr=attr)
    )
    unshare._apply_idmap_to_clone(11, 4242)
    assert seen["fd"] == 11 and seen["path"] == "" and seen["flags"] == idmap.AT_EMPTY_PATH
    assert seen["attr"].attr_set == idmap.MOUNT_ATTR_IDMAP
    assert seen["attr"].userns_fd == 33
    assert 33 in seen["close"]


def test_apply_idmap_to_clone_propagates_oserror(monkeypatch):
    import chroot_distro.syscalls.idmap as idmap

    monkeypatch.setattr(unshare.os, "open", lambda p, f: 33)
    monkeypatch.setattr(unshare.os, "close", lambda fd: None)

    def boom(fd, path, flags, attr):
        raise OSError(1, "permitted")

    monkeypatch.setattr(idmap, "mount_setattr", boom)
    with pytest.raises(OSError):
        unshare._apply_idmap_to_clone(11, 4242)
