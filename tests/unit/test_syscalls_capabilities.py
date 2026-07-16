from unittest.mock import patch

from chroot_distro.syscalls import capabilities as caps


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
    assert m.call_count == len(caps.CAPS_TO_DROP)


def test_drop_bounding_caps_negative_result_warns(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    with patch.object(caps, "libc_prctl", return_value=-1):
        warnings = caps.drop_bounding_caps()
    assert len(warnings) == len(caps.CAPS_TO_DROP)
    assert all("Failed to drop" in w for w in warnings)


def test_drop_bounding_caps_oserror_warns(monkeypatch):
    monkeypatch.delenv("CD_NO_CAP_DROP", raising=False)
    with patch.object(caps, "libc_prctl", side_effect=OSError(1, "boom")):
        warnings = caps.drop_bounding_caps()
    assert len(warnings) == len(caps.CAPS_TO_DROP)
    assert all("PR_CAPBSET_DROP" in w for w in warnings)
