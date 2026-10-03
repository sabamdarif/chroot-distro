from unittest.mock import patch

from chroot_distro.syscalls import capabilities as caps
from chroot_distro.syscalls._constants import (
    CAP_MKNOD,
    CAP_SYS_ADMIN,
    CAP_SYS_CHROOT,
    CAP_SYS_MODULE,
)


# ── should_drop_caps ──────────────────────────────────────────────────────────
def test_should_drop_caps_default(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    assert caps.should_drop_caps() is True


def test_should_drop_caps_opt_out(monkeypatch):
    monkeypatch.setenv("CD_NO_CAP_DROP", "1")
    assert caps.should_drop_caps() is False
    monkeypatch.setenv("CD_NO_CAP_DROP", "TRUE")
    assert caps.should_drop_caps() is False


def test_should_drop_caps_non_truthy(monkeypatch):
    monkeypatch.setenv("CD_NO_CAP_DROP", "0")
    assert caps.should_drop_caps() is True


# ── the allowlist computation ─────────────────────────────────────────────────
def test_caps_to_drop_is_kernel_range_minus_keep(monkeypatch):
    monkeypatch.setattr(caps, "cap_last_cap", lambda: 40)
    keep = frozenset(caps.CAPS_TO_KEEP)
    expected = tuple(c for c in range(0, 41) if c not in keep)
    assert caps.caps_to_drop() == expected


def test_caps_to_drop_fails_safe_on_future_caps(monkeypatch):
    monkeypatch.setattr(caps, "cap_last_cap", lambda: 42)
    dropped = set(caps.caps_to_drop())
    # caps 41 and 42 are unknown to the keep set, so they are dropped.
    assert 41 in dropped and 42 in dropped


def test_caps_to_drop_keeps_sys_admin_drops_mknod_and_chroot(monkeypatch):
    monkeypatch.setattr(caps, "cap_last_cap", lambda: 40)
    dropped = set(caps.caps_to_drop())
    assert CAP_SYS_ADMIN not in dropped
    assert CAP_MKNOD in dropped
    assert CAP_SYS_CHROOT in dropped
    assert CAP_SYS_MODULE in dropped


def test_cap_last_cap_reads_proc(monkeypatch):
    import builtins

    class FakeFile:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return "37\n"

    with patch.object(builtins, "open", return_value=FakeFile("/proc/sys/kernel/cap_last_cap")):
        assert caps.cap_last_cap() == 37


def test_cap_last_cap_falls_back_without_proc(monkeypatch):
    import builtins

    def failing_open(*a, **k):
        raise OSError("no /proc")

    with patch.object(builtins, "open", side_effect=failing_open):
        assert caps.cap_last_cap() == caps._FALLBACK_CAP_LAST_CAP


# ── drop_bounding_caps ────────────────────────────────────────────────────────
def test_drop_bounding_caps_opt_out_skips(monkeypatch):
    monkeypatch.setenv("CD_NO_CAP_DROP", "1")
    with patch.object(caps, "libc_prctl") as m:
        assert caps.drop_bounding_caps() == []
    m.assert_not_called()


def test_drop_bounding_caps_success(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    with patch.object(caps, "libc_prctl", return_value=0) as m:
        warnings = caps.drop_bounding_caps()
    assert warnings == []
    assert m.call_count == len(caps.caps_to_drop())


def test_drop_bounding_caps_negative_result_warns(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    monkeypatch.setattr(caps, "cap_last_cap", lambda: 40)
    with patch.object(caps, "libc_prctl", return_value=-1):
        warnings = caps.drop_bounding_caps()
    assert len(warnings) == len(caps.caps_to_drop())
    assert all("Failed to drop" in w for w in warnings)


def test_drop_bounding_caps_oserror_warns(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    monkeypatch.setattr(caps, "cap_last_cap", lambda: 40)
    with patch.object(caps, "libc_prctl", side_effect=OSError(1, "boom")):
        warnings = caps.drop_bounding_caps()
    assert len(warnings) == len(caps.caps_to_drop())
    assert all("PR_CAPBSET_DROP" in w for w in warnings)


def test_drop_bounding_caps_unnamed_cap_logs_by_number(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    with patch.object(caps, "libc_prctl", return_value=-1) as m:
        caps.drop_bounding_caps(caps=(37,))
    assert m.call_args.args[1] == 37
    # cap 37 (CAP_PERFMON) is not in the name table, so the warning names it
    # by number rather than crashing or logging blank.


# ── clear_ambient_caps ────────────────────────────────────────────────────────
def test_clear_ambient_caps_calls_prctl():
    with patch.object(caps, "libc_prctl", return_value=0) as m:
        caps.clear_ambient_caps()
    m.assert_called_once_with(47, 4)  # PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL


def test_clear_ambient_caps_tolerates_oserror():
    with patch.object(caps, "libc_prctl", side_effect=OSError(22, "no ambient support")):
        caps.clear_ambient_caps()  # must not raise
