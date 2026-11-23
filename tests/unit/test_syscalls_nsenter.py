import os
import subprocess
from unittest.mock import patch

from chroot_distro.syscalls import chroot, nsenter, seccomp
from chroot_distro.syscalls._constants import CLONE_NEWNS, CLONE_NEWUSER


# ── _ns_path ────────────────────────────────────────────────────────────────────
def test_ns_path_mount():
    assert nsenter._ns_path(1234, CLONE_NEWNS) == "/proc/1234/ns/mnt"


def test_ns_path_user():
    assert nsenter._ns_path(1, CLONE_NEWUSER) == "/proc/1/ns/user"


# ── check_ns_accessible ─────────────────────────────────────────────────────────
def test_check_ns_accessible_true():
    # Our own mount namespace is always openable.
    assert nsenter.check_ns_accessible(os.getpid(), CLONE_NEWNS) is True


def test_check_ns_accessible_false_for_bad_pid():
    assert nsenter.check_ns_accessible(2**30, CLONE_NEWNS) is False


# ── enter_namespaces: open failure closes fds and raises ─────────────────────────
def test_enter_namespaces_open_failure_raises():
    # PID that does not exist -> os.open raises in the collection loop.
    try:
        nsenter.enter_namespaces(2**30, CLONE_NEWNS)
    except OSError:
        pass
    else:
        raise AssertionError("expected OSError for inaccessible namespace")


# ── two-pass entry ordering: user namespace is deferred to pass 2 ────────────────
def test_enter_namespaces_defers_user_ns():
    # Mock the syscall layer so no real setns happens; assert user ns is only
    # entered in pass 2 (after the non-user namespaces).
    order = []

    def fake_setns(fd, nstype):
        order.append(nstype)

    fake_fd = 99
    with (
        patch("os.open", return_value=fake_fd),
        patch("os.close"),
        patch.object(nsenter, "py_setns", side_effect=fake_setns),
    ):
        nsenter.enter_namespaces(1, CLONE_NEWNS | CLONE_NEWUSER)

    # Mount ns entered first (pass 1), user ns last (pass 2).
    assert order[-1] == CLONE_NEWUSER
    assert CLONE_NEWNS in order


def test_enter_and_run_leaves_seccomp_to_chroot_setup(monkeypatch):
    def fake_exit(status):
        raise AssertionError(f"Unexpected child exit {status}")

    order = []
    monkeypatch.setattr(os, "isatty", lambda fd: False)
    monkeypatch.setattr(os, "fork", lambda: 0)
    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(chroot, "_close_fds_above", lambda keep: None)
    monkeypatch.setattr(chroot, "_try_exec", lambda *a: order.append("exec"))
    monkeypatch.setattr(chroot, "_wait_for_child_with_signals", lambda *a, **kw: 0)
    monkeypatch.setattr(nsenter, "enter_namespaces", lambda *a, **kw: order.append("setns"))
    monkeypatch.setattr(seccomp, "install_guest_filter", lambda: order.append("seccomp"))

    nsenter.enter_and_run_with_pty(42, CLONE_NEWNS, ["/bin/sh"], setup=lambda: order.append("setup"))

    assert order == ["setns", "setup", "exec"]
