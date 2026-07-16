import os

import pytest

from chroot_distro.helpers import isolation


# ── use_isolation_env_enabled / resolve_isolated ──────────────────────────────
@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", True), ("true", True), ("YES", True), ("on", True), ("0", False), ("", False), ("nope", False)],
)
def test_use_isolation_env_enabled(monkeypatch, value, expected):
    monkeypatch.setenv("CD_USE_ISOLATION", value)
    assert isolation.use_isolation_env_enabled() is expected


def test_use_isolation_env_unset(monkeypatch):
    monkeypatch.delenv("CD_USE_ISOLATION", raising=False)
    assert isolation.use_isolation_env_enabled() is False


class _Args:
    def __init__(self, isolated):
        self.isolated = isolated


def test_resolve_isolated_flag(monkeypatch):
    monkeypatch.delenv("CD_USE_ISOLATION", raising=False)
    assert isolation.resolve_isolated(_Args(True)) is True
    assert isolation.resolve_isolated(_Args(False)) is False


def test_resolve_isolated_env_overrides_flag(monkeypatch):
    monkeypatch.setenv("CD_USE_ISOLATION", "1")
    assert isolation.resolve_isolated(_Args(False)) is True


def test_resolve_isolated_missing_attr(monkeypatch):
    monkeypatch.delenv("CD_USE_ISOLATION", raising=False)
    assert isolation.resolve_isolated(object()) is False


# ── safe_hostname ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ubuntu", "ubuntu"),
        ("my-box.local", "my-box.local"),
        ("", "localhost"),
        ("has_underscore", "localhost"),  # underscore invalid in hostname
        ("bad space", "localhost"),
        ("a" * 64, "localhost"),  # label too long
        (".", "localhost"),  # empty label
    ],
)
def test_safe_hostname(name, expected):
    assert isolation.safe_hostname(name) == expected


# ── bind_is_recursive ─────────────────────────────────────────────────────────
def test_bind_is_recursive_run_root():
    run_root = "/rootfs/run"
    assert isolation.bind_is_recursive("/run", run_root, run_root) is True


def test_bind_is_recursive_under_run_root():
    run_root = "/rootfs/run"
    assert isolation.bind_is_recursive("/run/x", os.path.join(run_root, "x"), run_root) is True


def test_bind_is_recursive_wsl():
    assert isolation.bind_is_recursive("/usr/lib/wsl", "/rootfs/usr/lib/wsl", "/rootfs/run") is True


def test_bind_is_recursive_plain_is_false():
    assert isolation.bind_is_recursive("/etc/hosts", "/rootfs/etc/hosts", "/rootfs/run") is False


def test_bind_is_recursive_userns_pseudo():
    assert isolation.bind_is_recursive("/sys", "/rootfs/sys", "/rootfs/run", use_userns=True) is True
    assert isolation.bind_is_recursive("/dev", "/rootfs/dev", "/rootfs/run", use_userns=True) is True
    # Without userns, /sys is not forced recursive.
    assert isolation.bind_is_recursive("/sys", "/rootfs/sys", "/rootfs/run", use_userns=False) is False
