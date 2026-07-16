from types import SimpleNamespace

from chroot_distro.commands import info
from chroot_distro.commands.kernel_config import (
    CONFIG_BUILTIN,
    CONFIG_MODULE,
    CONFIG_UNKNOWN,
    PROBE_ABSENT,
    PROBE_PRESENT,
)


# ── _read_sysctl_int ────────────────────────────────────────────────────────────
def test_read_sysctl_int_ok(tmp_path):
    p = tmp_path / "knob"
    p.write_text("42\n")
    assert info._read_sysctl_int(str(p)) == 42


def test_read_sysctl_int_bad_value(tmp_path):
    p = tmp_path / "knob"
    p.write_text("not-a-number")
    assert info._read_sysctl_int(str(p)) is None


def test_read_sysctl_int_missing(tmp_path):
    assert info._read_sysctl_int(str(tmp_path / "nope")) is None


# ── _userns_knob_caps ────────────────────────────────────────────────────────────
def test_userns_knob_caps_disabled_and_blocked(monkeypatch):
    values = {
        "/proc/sys/user/max_user_namespaces": 0,
        "/proc/sys/kernel/unprivileged_userns_clone": 0,
    }
    monkeypatch.setattr(info, "_read_sysctl_int", lambda path: values.get(path))
    caps = info._userns_knob_caps()
    assert caps[0].label == "max_user_namespaces"
    assert caps[0].level == "warn"
    assert caps[1].label == "unprivileged_userns_clone"
    assert caps[1].level == "info"


def test_userns_knob_caps_enabled(monkeypatch):
    values = {
        "/proc/sys/user/max_user_namespaces": 1000,
        "/proc/sys/kernel/unprivileged_userns_clone": 1,
    }
    monkeypatch.setattr(info, "_read_sysctl_int", lambda path: values.get(path))
    caps = info._userns_knob_caps()
    assert [c.level for c in caps] == ["ok", "ok"]


def test_userns_knob_caps_absent(monkeypatch):
    monkeypatch.setattr(info, "_read_sysctl_int", lambda path: None)
    assert info._userns_knob_caps() == []


# ── _free_disk ───────────────────────────────────────────────────────────────────
def test_free_disk_warns_under_1gib(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: True)
    monkeypatch.setattr(
        info.shutil, "disk_usage", lambda p: SimpleNamespace(total=100 << 30, free=512 << 20, used=0)
    )
    value, level = info._free_disk("/data")
    assert level == "warn"
    assert "free of" in value


def test_free_disk_info_when_ample(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: True)
    monkeypatch.setattr(
        info.shutil, "disk_usage", lambda p: SimpleNamespace(total=100 << 30, free=50 << 30, used=0)
    )
    _value, level = info._free_disk("/data")
    assert level == "info"


# ── _format_image_table ──────────────────────────────────────────────────────────
def test_format_image_table_has_header_and_rows():
    imgs = [
        info._ImageInfo(name="ubuntu", size="120M", arch="amd64", source="docker", status="idle"),
        info._ImageInfo(name="a", size="1G", arch="arm64", source="local", status="in use (1)"),
    ]
    lines = info._format_image_table(imgs)
    assert len(lines) == 3  # header + 2 rows
    assert "NAME" in lines[0]
    assert "ubuntu" in lines[1]


# ── _running_summary ──────────────────────────────────────────────────────────────
def test_running_summary_counts_non_idle():
    imgs = [
        info._ImageInfo(name="a", status="idle"),
        info._ImageInfo(name="b", status="in use (2)"),
        info._ImageInfo(name="c", status="in use (1)"),
    ]
    assert info._running_summary(imgs) == 2


# ── _flag_status ───────────────────────────────────────────────────────────────────
def _flag(name="PID_NS", required=True):
    return SimpleNamespace(name=name, required=required, purpose="x")


def test_flag_status_builtin(monkeypatch):
    monkeypatch.setattr(info, "lookup_flag", lambda parsed, name: CONFIG_BUILTIN)
    glyph, color, state, missing = info._flag_status(_flag(), {"PID_NS": "y"})
    assert color == "GREEN" and state == "enabled" and missing is False


def test_flag_status_module(monkeypatch):
    monkeypatch.setattr(info, "lookup_flag", lambda parsed, name: CONFIG_MODULE)
    _g, color, state, missing = info._flag_status(_flag(), {"PID_NS": "m"})
    assert color == "GREEN" and state == "enabled (module)" and missing is False


def test_flag_status_missing_required(monkeypatch):
    monkeypatch.setattr(info, "lookup_flag", lambda parsed, name: "n")
    _g, color, _s, missing = info._flag_status(_flag(required=True), {"PID_NS": "n"})
    assert color == "RED" and missing is True


def test_flag_status_missing_optional(monkeypatch):
    monkeypatch.setattr(info, "lookup_flag", lambda parsed, name: "n")
    _g, color, _s, missing = info._flag_status(_flag(required=False), {"PID_NS": "n"})
    assert color == "YELLOW" and missing is False


def test_flag_status_unknown_in_config(monkeypatch):
    monkeypatch.setattr(info, "lookup_flag", lambda parsed, name: CONFIG_UNKNOWN)
    _g, color, state, missing = info._flag_status(_flag(), {})
    assert color == "CYAN" and state == "unknown" and missing is False


def test_flag_status_runtime_present(monkeypatch):
    monkeypatch.setattr(info, "probe_flag_runtime", lambda name: PROBE_PRESENT)
    _g, color, state, missing = info._flag_status(_flag(), None)
    assert color == "GREEN" and "runtime" in state and missing is False


def test_flag_status_runtime_absent_required(monkeypatch):
    monkeypatch.setattr(info, "probe_flag_runtime", lambda name: PROBE_ABSENT)
    _g, color, _s, missing = info._flag_status(_flag(required=True), None)
    assert color == "RED" and missing is True
