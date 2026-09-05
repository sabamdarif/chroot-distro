import os
from unittest.mock import patch

from chroot_distro.syscalls import unshare
from chroot_distro.syscalls._constants import CLONE_NEWNS, CLONE_NEWPID


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
