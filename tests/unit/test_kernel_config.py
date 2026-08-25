import gzip
from unittest.mock import mock_open, patch

import chroot_distro.commands.info as info
import chroot_distro.commands.kernel_config as kc

_SAMPLE = "\n".join(
    [
        "# Auto-generated kernel config",
        "CONFIG_NAMESPACES=y",
        "CONFIG_PID_NS=y",
        "CONFIG_UTS_NS=y",
        "CONFIG_IPC_NS=y",
        "# CONFIG_USER_NS is not set",
        "CONFIG_PROC_FS=y",
        "CONFIG_SYSFS=y",
        "CONFIG_TMPFS=y",
        "CONFIG_CGROUPS=y",
        "CONFIG_CGROUP_NS=m",
    ]
)


def _capture(lines):
    return lambda *a: lines.append(a[0] if a else "")


def test_parse_kernel_config_recognizes_y_m_and_not_set():
    parsed = kc.parse_kernel_config(_SAMPLE)
    assert parsed["NAMESPACES"] == kc.CONFIG_BUILTIN
    assert parsed["CGROUP_NS"] == kc.CONFIG_MODULE
    assert parsed["USER_NS"] == kc.CONFIG_MISSING
    # An option absent from the text is simply not in the dict.
    assert "NET_NS" not in parsed


def test_lookup_flag_handles_unknown_and_absent():
    parsed = kc.parse_kernel_config(_SAMPLE)
    assert kc.lookup_flag(parsed, "PID_NS") == kc.CONFIG_BUILTIN
    # Absent from a readable config -> treated as missing.
    assert kc.lookup_flag(parsed, "NET_NS") == kc.CONFIG_MISSING
    # No config at all -> unknown.
    assert kc.lookup_flag(None, "PID_NS") == kc.CONFIG_UNKNOWN


def test_find_kernel_config_reads_plain_file(tmp_path):
    cfg = tmp_path / ".config"
    cfg.write_text(_SAMPLE)
    with patch.dict(kc.os.environ, {"CONFIG": str(cfg)}, clear=False):
        path, text = kc.find_kernel_config()
    assert path == str(cfg)
    assert "CONFIG_NAMESPACES=y" in text


def test_find_kernel_config_reads_gzip(tmp_path):
    cfg = tmp_path / "config.gz"
    with gzip.open(cfg, "wt", encoding="utf-8") as fh:
        fh.write(_SAMPLE)
    with patch.dict(kc.os.environ, {"CONFIG": str(cfg)}, clear=False):
        path, text = kc.find_kernel_config()
    assert path == str(cfg)
    assert "CONFIG_PID_NS=y" in text


def test_find_kernel_config_returns_none_when_absent(tmp_path):
    missing = tmp_path / "does-not-exist"
    with (
        patch.dict(kc.os.environ, {"CONFIG": str(missing)}, clear=False),
        patch.object(kc, "_candidate_config_paths", return_value=[]),
    ):
        path, text = kc.find_kernel_config()
    assert path is None
    assert text is None


def test_render_kernel_config_reports_missing_required():
    # PID_NS is required and missing in this partial config.
    partial = "\n".join(
        [
            "CONFIG_NAMESPACES=y",
            "CONFIG_PROC_FS=y",
            "CONFIG_SYSFS=y",
            "CONFIG_UNIX98_PTYS=y",
        ]
    )
    lines: list[str] = []
    with (
        patch.object(info, "find_kernel_config", return_value=("/proc/config.gz", partial)),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_config()
    blob = "\n".join(lines)
    assert "CONFIG_PID_NS" in blob
    assert "cannot work fully without" in blob


def test_probe_flag_runtime_namespaces_from_dir_listing():
    # Namespace present when listed under /proc/self/ns (the reliable path).
    with patch.object(kc, "_ns_dir_entries", return_value={"mnt", "pid", "uts", "ipc"}):
        assert kc.probe_flag_runtime("PID_NS") == kc.PROBE_PRESENT
        assert kc.probe_flag_runtime("NAMESPACES") == kc.PROBE_PRESENT
        assert kc.probe_flag_runtime("NET_NS") == kc.PROBE_ABSENT


def test_probe_flag_runtime_namespaces_lexists_fallback():
    # When the dir cannot be listed, fall back to lexists on the link itself.
    with (
        patch.object(kc, "_ns_dir_entries", return_value=None),
        patch.object(kc.os.path, "lexists", side_effect=lambda p: p.endswith("/ns/pid")),
    ):
        assert kc.probe_flag_runtime("PID_NS") == kc.PROBE_PRESENT
        assert kc.probe_flag_runtime("UTS_NS") == kc.PROBE_ABSENT


def test_probe_flag_runtime_filesystems():
    # Present when listed in /proc/filesystems.
    with patch.object(kc, "_proc_filesystems", return_value={"proc", "sysfs", "tmpfs"}):
        assert kc.probe_flag_runtime("PROC_FS") == kc.PROBE_PRESENT
        # devtmpfs not listed and no mount hint -> absent.
        with patch.object(kc.os.path, "isdir", return_value=False):
            assert kc.probe_flag_runtime("DEVTMPFS") == kc.PROBE_ABSENT

    # Fallback to mounts when /proc/filesystems is unreadable (None)
    with (
        patch.object(kc, "_proc_filesystems", return_value=None),
        patch.object(kc, "_has_fs_in_mounts", return_value=True),
    ):
        assert kc.probe_flag_runtime("TMPFS") == kc.PROBE_PRESENT

    with (
        patch.object(kc, "_proc_filesystems", return_value=None),
        patch.object(kc, "_has_fs_in_mounts", return_value=False),
    ):
        assert kc.probe_flag_runtime("TMPFS") == kc.PROBE_UNKNOWN


def test_has_fs_in_mounts():
    mock_mounts = "rootfs / rootfs rw 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
    with patch("builtins.open", mock_open(read_data=mock_mounts)):
        assert kc._has_fs_in_mounts("tmpfs") is True
        assert kc._has_fs_in_mounts("devtmpfs") is False


def test_probe_flag_runtime_filesystem_uses_mount_hint_when_unreadable():
    # /proc/filesystems unreadable (None) but the canonical mount exists.
    with (
        patch.object(kc, "_proc_filesystems", return_value=None),
        patch.object(kc, "_has_fs_in_mounts", return_value=False),
        patch.object(kc.os.path, "isdir", side_effect=lambda p: p == "/proc"),
    ):
        assert kc.probe_flag_runtime("PROC_FS") == kc.PROBE_PRESENT
        assert kc.probe_flag_runtime("TMPFS") == kc.PROBE_UNKNOWN


def test_render_kernel_config_falls_back_to_runtime_probe():
    """With no static config, the section must probe the live kernel rather
    than giving up, and a confirmed-absent required flag still blocks."""
    lines: list[str] = []

    def fake_probe(name):
        # PID_NS confirmed absent (required) -> must be flagged; others present.
        return kc.PROBE_ABSENT if name == "PID_NS" else kc.PROBE_PRESENT

    with (
        patch.object(info, "find_kernel_config", return_value=(None, None)),
        patch.object(info, "probe_flag_runtime", side_effect=fake_probe),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_config()
    blob = "\n".join(lines)
    assert "probing the running kernel" in blob
    assert "available (runtime)" in blob
    assert "cannot work fully without" in blob
    assert "CONFIG_PID_NS" in blob


def test_render_kernel_config_runtime_unknown_does_not_block():
    """A merely-unknown required flag (probe inconclusive) must NOT be reported
    as blocking isolation."""
    lines: list[str] = []
    with (
        patch.object(info, "find_kernel_config", return_value=(None, None)),
        patch.object(info, "probe_flag_runtime", return_value=kc.PROBE_UNKNOWN),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_config()
    blob = "\n".join(lines)
    assert "cannot work fully without" not in blob
    assert "All kernel options required for namespace isolation are present" in blob


def test_render_kernel_config_all_present_is_ok():
    full = "\n".join("CONFIG_" + flag.name + "=y" for group in kc.KERNEL_FLAG_GROUPS for flag in group.flags)
    lines: list[str] = []
    with (
        patch.object(info, "find_kernel_config", return_value=("/boot/config-test", full)),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_config()
    assert "All kernel options required for namespace isolation are present" in "\n".join(lines)


def test_probe_flag_runtime_userns():
    # Case 1: max_user_namespaces exists and is > 0
    mock_file = mock_open(read_data="1000\n").return_value
    real_open = open

    def fake_open_present(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            return mock_file
        return real_open(path, *a, **k)

    with patch("builtins.open", side_effect=fake_open_present):
        assert kc.probe_flag_runtime("USER_NS") == kc.PROBE_PRESENT

    # Case 2: max_user_namespaces exists and is 0
    mock_file_zero = mock_open(read_data="0\n").return_value

    def fake_open_absent(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            return mock_file_zero
        return real_open(path, *a, **k)

    with patch("builtins.open", side_effect=fake_open_absent):
        assert kc.probe_flag_runtime("USER_NS") == kc.PROBE_ABSENT

    # Case 3: max_user_namespaces is missing (OSError) and /proc/self/ns/user is present
    def fake_open_oserror(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            raise OSError
        return real_open(path, *a, **k)

    with (
        patch("builtins.open", side_effect=fake_open_oserror),
        patch.object(kc, "_ns_dir_entries", return_value={"mnt", "user"}),
    ):
        assert kc.probe_flag_runtime("USER_NS") == kc.PROBE_PRESENT

    # Case 4: max_user_namespaces is missing (OSError) and /proc/self/ns/user is absent
    with (
        patch("builtins.open", side_effect=fake_open_oserror),
        patch.object(kc, "_ns_dir_entries", return_value={"mnt"}),
    ):
        assert kc.probe_flag_runtime("USER_NS") == kc.PROBE_ABSENT


# ── kernel_version_tuple / probe_devpts_multi_instance ─────────────────────────
def test_kernel_version_tuple_parses_release():
    with patch.object(kc.os, "uname") as m:
        m.return_value.release = "4.4.302-gfbd6a732a614"
        assert kc.kernel_version_tuple() == (4, 4)


def test_kernel_version_tuple_unparseable_is_zero():
    with patch.object(kc.os, "uname") as m:
        m.return_value.release = "weird"
        assert kc.kernel_version_tuple() == (0, 0)


def test_devpts_probe_modern_kernel_short_circuits():
    # >= 4.7: per-mount instances are built in; no mount probe needed.
    with patch.object(kc, "kernel_version_tuple", return_value=(4, 19)):
        assert kc.probe_devpts_multi_instance() == kc.PROBE_PRESENT


def test_devpts_probe_old_kernel_without_root_is_unknown():
    with (
        patch.object(kc, "kernel_version_tuple", return_value=(4, 4)),
        patch.object(kc.os, "getuid", return_value=1000),
    ):
        assert kc.probe_devpts_multi_instance() == kc.PROBE_UNKNOWN
