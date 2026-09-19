from types import SimpleNamespace
from unittest.mock import patch

from chroot_distro.commands import info
from chroot_distro.commands.kernel_config import (
    PROBE_ABSENT,
    PROBE_PRESENT,
    PROBE_UNKNOWN,
    KernelFeature,
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
    monkeypatch.setattr(info.shutil, "disk_usage", lambda p: SimpleNamespace(total=100 << 30, free=512 << 20, used=0))
    value, level = info._free_disk("/data")
    assert level == "warn"
    assert "free of" in value


def test_free_disk_info_when_ample(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: True)
    monkeypatch.setattr(info.shutil, "disk_usage", lambda p: SimpleNamespace(total=100 << 30, free=50 << 30, used=0))
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


# ── _feature_status ───────────────────────────────────────────────────────────────
def _feature(key="pid", required=True):
    return KernelFeature(key=key, label="PID namespace", purpose="x", required=required)


def test_feature_status_present(monkeypatch):
    _g, color, state, missing = info._feature_status(_feature(), PROBE_PRESENT)
    assert color == "GREEN" and state == "available" and missing is False


def test_feature_status_absent_required(monkeypatch):
    _g, color, _s, missing = info._feature_status(_feature(required=True), PROBE_ABSENT)
    assert color == "RED" and missing is True


def test_feature_status_absent_optional(monkeypatch):
    _g, color, _s, missing = info._feature_status(_feature(required=False), PROBE_ABSENT)
    assert color == "YELLOW" and missing is False


def test_feature_status_unknown_never_counts(monkeypatch):
    _g, color, state, missing = info._feature_status(_feature(), PROBE_UNKNOWN)
    assert color == "CYAN" and state == "unknown" and missing is False


def test_feature_status_names_the_devpts_shape(monkeypatch):
    feat = KernelFeature(key="devpts-multi", label="devpts multi-instance", purpose="x", required=False)
    _g, _c, state, missing = info._feature_status(feat, PROBE_PRESENT)
    assert state == "per-mount instances" and missing is False
    _g, color, state, missing = info._feature_status(feat, PROBE_ABSENT)
    assert color == "YELLOW" and "single shared instance" in state and missing is False


# ── _has_shell ──────────────────────────────────────────────────────────────────
def test_has_shell_reads_a_shell_inside_the_rootfs(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "sh").touch()
    assert info._has_shell(str(tmp_path)) is True


def test_has_shell_is_false_for_a_rootfs_that_ships_none(tmp_path):
    # A scratch or distroless rootfs: the app's own files and nothing else.
    (tmp_path / "hello.txt").write_text("hi")
    assert info._has_shell(str(tmp_path)) is False


def test_render_images_says_how_a_shell_less_image_is_started():
    img = info._ImageInfo(
        name="hello-world",
        size="1.0 KiB",
        arch="aarch64",
        has_shell=False,
        has_command=True,
    )
    with patch.object(info, "msg") as mock_msg:
        info._render_images([img])
    rendered = " ".join(str(c.args[0]) for c in mock_msg.call_args_list if c.args)
    assert "Shell:" in rendered
    assert "start it with 'run'" in rendered
