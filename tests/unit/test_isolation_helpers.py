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


# ── split_dev_binds ────────────────────────────────────────────────────────────
def test_split_dev_binds_routes_under_dev(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "dev").mkdir(parents=True)
    (rootfs / "data").mkdir()
    pairs = [
        ("/dev/dri/renderD128", str(rootfs / "dev/dri/renderD128")),
        ("/dev/binderfs", str(rootfs / "dev/binderfs")),
        ("/data", str(rootfs / "data")),
    ]
    rest, dev = isolation.split_dev_binds(pairs, str(rootfs))
    assert [s for s, _ in dev] == ["/dev/dri/renderD128", "/dev/binderfs"]
    assert [s for s, _ in rest] == ["/data"]


def test_split_dev_binds_keeps_dev_root_itself(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "dev").mkdir(parents=True)
    rest, dev = isolation.split_dev_binds([("/dev", str(rootfs / "dev"))], str(rootfs))
    assert [s for s, _ in dev] == ["/dev"]
    assert rest == []


# ── apply_special_mounts fallbacks ─────────────────────────────────────────────
class _FakeHolder:
    """Runs the closure like holder.call does, without namespaces."""

    def __init__(self):
        self.calls = 0

    def call(self, fn, prepare=None):
        self.calls += 1
        if prepare is not None:
            prepare()
        return fn()


def _specials_stub(rootfs, **kw):
    from chroot_distro.commands.login.bindings import SpecialMount

    return [
        SpecialMount(fstype="tmpfs", source="tmpfs", target="/dev", options="nosuid", optional=False),
        SpecialMount(fstype="sysfs", source="sysfs", target="/sys", options="ro,nosuid", optional=True),
    ]


def test_failed_dev_tmpfs_falls_back_to_host_bind(monkeypatch, tmp_path):
    from chroot_distro.commands.login import bindings

    monkeypatch.setattr(bindings, "get_special_mounts", _specials_stub)
    monkeypatch.setattr(isolation, "_apply_masked_paths", lambda *a, **kw: None)
    monkeypatch.setattr(isolation.mount_manager, "create_dev_nodes", lambda *a, **kw: None)
    monkeypatch.setattr(
        isolation.mount_manager,
        "apply_special_mount",
        lambda rootfs, sm, **kw: False,
    )
    mounts = []
    monkeypatch.setattr(
        isolation.mount_manager,
        "safe_mount",
        lambda src, dst, **kw: mounts.append(src),
    )

    isolation.apply_special_mounts(str(tmp_path), None, max_isolation=False, minimal=True)

    assert "/dev" in mounts  # the host bind fallback
    assert "/sys" in mounts  # sysfs refused too -> host /sys bind


def test_failed_sysfs_alone_binds_host_sys(monkeypatch, tmp_path):
    from chroot_distro.commands.login import bindings

    monkeypatch.setattr(bindings, "get_special_mounts", _specials_stub)
    monkeypatch.setattr(isolation, "_apply_masked_paths", lambda *a, **kw: None)
    monkeypatch.setattr(isolation.mount_manager, "create_dev_nodes", lambda *a, **kw: None)
    monkeypatch.setattr(
        isolation.mount_manager,
        "apply_special_mount",
        lambda rootfs, sm, **kw: sm.fstype != "sysfs",
    )
    mounts = []
    monkeypatch.setattr(
        isolation.mount_manager,
        "safe_mount",
        lambda src, dst, **kw: mounts.append(src),
    )
    monkeypatch.setattr(isolation.mount_manager, "make_rslave", lambda *a, **kw: True)
    monkeypatch.setattr(isolation, "remount_bind", lambda *a, **kw: None)

    isolation.apply_special_mounts(str(tmp_path), None, max_isolation=False, minimal=True)

    assert mounts == ["/sys"]  # tmpfs /dev succeeded, only sysfs fell back


def test_ensure_dev_symlinks_creates_missing_links(tmp_path):
    holder = _FakeHolder()
    dev = tmp_path / "dev"
    dev.mkdir()

    isolation._ensure_dev_symlinks(str(tmp_path), holder)

    assert (dev / "fd").is_symlink()
    assert os.readlink(dev / "fd") == "/proc/self/fd"
    assert os.readlink(dev / "stdin") == "/proc/self/fd/0"
    assert os.readlink(dev / "stdout") == "/proc/self/fd/1"
    assert os.readlink(dev / "stderr") == "/proc/self/fd/2"


def test_ensure_dev_symlinks_keeps_existing_entries(tmp_path):
    dev = tmp_path / "dev"
    dev.mkdir()
    (dev / "stdin").write_text("kept")

    isolation._ensure_dev_symlinks(str(tmp_path), None)

    assert (dev / "stdin").read_text() == "kept"  # never clobbered
    assert (dev / "fd").is_symlink()
