from unittest.mock import mock_open, patch

import chroot_distro.commands.info as info
import chroot_distro.commands.kernel_config as kc


def _capture(lines):
    return lambda *a: lines.append(a[0] if a else "")


# ── probe_feature: namespaces ────────────────────────────────────────────────────
def test_namespace_absent_when_not_listed_and_no_fork():
    """A namespace missing from /proc/self/ns is a negative answer on its own."""
    with (
        patch.object(kc, "_ns_dir_entries", return_value={"mnt"}),
        patch.object(kc, "_namespace_works") as works,
    ):
        assert kc.probe_feature("pid") == kc.PROBE_ABSENT
        works.assert_not_called()


def test_namespace_present_only_when_unshare_succeeds():
    """Presence in /proc/self/ns is not enough: the flag has to be accepted."""
    for accepted, expected in ((kc.CLONE_NEWPID, kc.PROBE_PRESENT), (0, kc.PROBE_ABSENT)):
        with (
            patch.object(kc, "_ns_dir_entries", return_value={"mnt", "pid"}),
            patch.object(kc, "_namespace_works", return_value=bool(accepted)),
        ):
            assert kc.probe_feature("pid") == expected


def test_namespace_probed_when_listing_unavailable():
    """An unlistable /proc/self/ns is not an answer, so the flag is tried."""
    with (
        patch.object(kc, "_ns_dir_entries", return_value=None),
        patch.object(kc, "_namespace_works", return_value=True) as works,
    ):
        assert kc.probe_feature("uts") == kc.PROBE_PRESENT
        works.assert_called_once_with(kc.CLONE_NEWUTS)


# ── probe_feature: filesystems ───────────────────────────────────────────────────
def test_filesystem_present_from_proc_filesystems():
    with (
        patch.object(kc, "_proc_filesystems", return_value={"proc", "sysfs", "tmpfs"}),
        patch.object(kc.os.path, "isdir", return_value=False),
    ):
        assert kc.probe_feature("proc") == kc.PROBE_PRESENT
        # Not listed and nothing mounted at the hint -> a real absence.
        assert kc.probe_feature("devtmpfs") == kc.PROBE_ABSENT


def test_filesystem_present_from_mount_hint():
    with (
        patch.object(kc, "_proc_filesystems", return_value=set()),
        patch.object(kc.os.path, "isdir", side_effect=lambda p: p == "/dev/pts"),
    ):
        assert kc.probe_feature("devpts") == kc.PROBE_PRESENT
        assert kc.probe_feature("tmpfs") == kc.PROBE_ABSENT  # no hint to check


def test_filesystem_unknown_when_proc_unreadable():
    """"Cannot tell" stays distinct from "absent" when nothing can be read."""
    with (
        patch.object(kc, "_proc_filesystems", return_value=None),
        patch.object(kc, "_has_fs_in_mounts", return_value=True),
    ):
        assert kc.probe_feature("tmpfs") == kc.PROBE_PRESENT

    with (
        patch.object(kc, "_proc_filesystems", return_value=None),
        patch.object(kc, "_has_fs_in_mounts", return_value=False),
        patch.object(kc.os.path, "isdir", return_value=False),
    ):
        assert kc.probe_feature("tmpfs") == kc.PROBE_UNKNOWN


def test_has_fs_in_mounts():
    mock_mounts = "rootfs / rootfs rw 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
    with patch("builtins.open", mock_open(read_data=mock_mounts)):
        assert kc._has_fs_in_mounts("tmpfs") is True
        assert kc._has_fs_in_mounts("devtmpfs") is False


# ── probe_feature: cgroups and the unknown key ───────────────────────────────────
def test_cgroup_filesystem_from_type_or_mount_dir():
    with (
        patch.object(kc, "_proc_filesystems", return_value={"cgroup2"}),
        patch.object(kc.os.path, "isdir", return_value=False),
    ):
        assert kc.probe_feature("cgroup-fs") == kc.PROBE_PRESENT

    with (
        patch.object(kc, "_proc_filesystems", return_value=set()),
        patch.object(kc.os.path, "isdir", side_effect=lambda p: p == "/sys/fs/cgroup"),
    ):
        assert kc.probe_feature("cgroup-fs") == kc.PROBE_PRESENT

    with (
        patch.object(kc, "_proc_filesystems", return_value=set()),
        patch.object(kc.os.path, "isdir", return_value=False),
    ):
        assert kc.probe_feature("cgroup-fs") == kc.PROBE_ABSENT


def test_cgroup_namespace_answers_through_its_own_probe():
    with (
        patch.object(kc, "_ns_dir_entries", return_value={"mnt", "cgroup"}),
        patch.object(kc, "_namespace_works", return_value=True),
    ):
        assert kc.probe_feature("cgroup") == kc.PROBE_PRESENT


def test_unlisted_key_is_unknown():
    assert kc.probe_feature("NOT_A_FEATURE") == kc.PROBE_UNKNOWN


def test_devpts_multi_instance_answers_through_probe_feature():
    with patch.object(kc, "probe_devpts_multi_instance", return_value=kc.PROBE_ABSENT):
        assert kc.probe_feature("devpts-multi") == kc.PROBE_ABSENT


# ── the rendered section ─────────────────────────────────────────────────────────
def test_render_kernel_support_reports_missing_required():
    def fake_probe(key):
        return kc.PROBE_ABSENT if key == "pid" else kc.PROBE_PRESENT

    lines: list[str] = []
    with (
        patch.object(info, "probe_feature", side_effect=fake_probe),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_support()
    blob = "\n".join(lines)
    assert "PID namespace" in blob
    assert "cannot work fully without" in blob
    assert "PID namespace" in blob.split("cannot work fully without")[1]


def test_render_kernel_support_unknown_does_not_block():
    """A probe that could not decide is not evidence of a missing feature."""
    lines: list[str] = []
    with (
        patch.object(info, "probe_feature", return_value=kc.PROBE_UNKNOWN),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_support()
    blob = "\n".join(lines)
    assert "cannot work fully without" not in blob
    assert "unknown" in blob
    assert "All kernel features required for namespace isolation are available" in blob


def test_render_kernel_support_all_present_is_ok():
    lines: list[str] = []
    with (
        patch.object(info, "probe_feature", return_value=kc.PROBE_PRESENT),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_support()
    assert "All kernel features required for namespace isolation are available" in "\n".join(lines)


def test_render_kernel_support_states_the_devpts_shape():
    lines: list[str] = []
    with (
        patch.object(info, "probe_feature", return_value=kc.PROBE_ABSENT),
        patch.object(info, "msg", side_effect=_capture(lines)),
    ):
        info._render_kernel_support()
    blob = "\n".join(lines)
    assert "single shared instance" in blob
    # Optional, so it must not be listed as blocking isolation.
    assert "devpts multi-instance" not in blob.split("cannot work fully without")[-1]


# ── kernel_version_tuple / probe_devpts_multi_instance ───────────────────────────
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
