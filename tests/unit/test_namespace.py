"""Unit tests for namespace isolation helpers."""

from unittest.mock import MagicMock, mock_open, patch

import pytest

from chroot_distro.helpers import namespace as ns


def test_long_flags_to_nsenter_short():
    flags = ["--mount", "--pid", "--uts", "--ipc"]
    assert ns.long_flags_to_nsenter(flags, use_long=False) == ["-m", "-p", "-u", "-i"]


def test_holder_unshare_argv_adds_fork_with_pid():
    argv = ns._holder_unshare_argv("unshare", ["--pid", "--mount"])
    assert argv == ["unshare", "--fork", "--pid", "--mount", "sleep", ns.HOLDER_SLEEP_SECONDS]


def test_holder_unshare_argv_no_duplicate_fork():
    argv = ns._holder_unshare_argv("unshare", ["--fork", "--mount"])
    assert argv.count("--fork") == 1
    assert argv[-2:] == ["sleep", ns.HOLDER_SLEEP_SECONDS]


def test_holder_uses_finite_sleep_not_infinity():
    """Android toybox `sleep` rejects 'infinity'; the holder must use a
    finite numeric duration."""
    argv = ns._holder_unshare_argv("unshare", ["--mount"])
    assert "infinity" not in argv
    assert argv[-1].isdigit()


def test_is_sleep_holder_matches_finite_and_legacy():
    def check(arg: str) -> bool:
        with (
            patch.object(ns, "_proc_comm", return_value="sleep"),
            patch("builtins.open", mock_open(read_data=f"sleep\x00{arg}\x00")),
        ):
            return ns._is_sleep_infinity_holder(1234)

    assert check(ns.HOLDER_SLEEP_SECONDS) is True
    assert check("infinity") is True
    assert check("5") is False


def test_pick_new_holder_pid():
    before = {10, 20}
    with patch.object(ns, "_snapshot_sleep_infinity_pids", return_value={10, 20, 99}):
        assert ns._pick_new_holder_pid(before) == 99


def test_pick_new_holder_pid_from_launcher_child():
    before: set[int] = set()
    with (
        patch.object(ns, "_snapshot_sleep_infinity_pids", return_value=set()),
        patch.object(ns, "_read_host_child_pids", side_effect=lambda pid: [12345] if pid == 999 else []),
        patch.object(ns, "_is_sleep_infinity_holder", side_effect=lambda pid: pid == 12345),
    ):
        assert ns._pick_new_holder_pid(before, launcher_pid=999) == 12345


def test_pick_new_holder_pid_grandchild_via_fork():
    """unshare --pid --fork re-parents sleep one level below: 999 -> 500 -> 12345."""
    before: set[int] = set()
    tree = {999: [500], 500: [12345], 12345: []}
    with (
        patch.object(ns, "_snapshot_sleep_infinity_pids", return_value=set()),
        patch.object(ns, "_read_host_child_pids", side_effect=lambda pid: tree.get(pid, [])),
        patch.object(ns, "_is_sleep_infinity_holder", side_effect=lambda pid: pid == 12345),
    ):
        assert ns._pick_new_holder_pid(before, launcher_pid=999) == 12345


def test_pick_new_holder_prefers_descendant_over_stale():
    """Pre-existing/leaked sleep holders must not be chosen over the real
    descendant of the launched unshare process."""
    before = {111, 222}  # stale leaked holders captured in the snapshot
    tree = {999: [777], 777: []}
    with (
        # Global scan would surface stale 111/222 plus the new 777.
        patch.object(ns, "_snapshot_sleep_infinity_pids", return_value={111, 222, 777}),
        patch.object(ns, "_read_host_child_pids", side_effect=lambda pid: tree.get(pid, [])),
        patch.object(ns, "_is_sleep_infinity_holder", side_effect=lambda pid: pid in (111, 222, 777)),
    ):
        assert ns._pick_new_holder_pid(before, launcher_pid=999) == 777


def test_long_flags_to_nsenter_long():
    flags = ["--mount", "--pid"]
    assert ns.long_flags_to_nsenter(flags, use_long=True) == ["--mount", "--pid"]


@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_unshare_flags_requires_mount(mock_run):
    def side_effect(cmd, **kwargs):
        flag = cmd[1] if len(cmd) > 1 else ""
        rc = 0 if flag in ("--mount", "--pid") else 1
        return MagicMock(returncode=rc)

    mock_run.side_effect = side_effect
    flags = ns.probe_unshare_flags()
    assert "--mount" in flags
    assert "--pid" in flags


@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_unshare_flags_fails_without_mount(mock_run):
    mock_run.return_value = MagicMock(returncode=1)
    with pytest.raises(ns.NamespaceError, match="Mount namespace"):
        ns.probe_unshare_flags()


@patch("chroot_distro.helpers.namespace._resolve_unshare", return_value="unshare")
@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_namespace_support_all_present(mock_run, _unshare):
    mock_run.return_value = MagicMock(returncode=0)
    assert ns.probe_namespace_support() == []


@patch("chroot_distro.helpers.namespace._resolve_unshare", return_value="unshare")
@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_namespace_support_reports_missing(mock_run, _unshare):
    def side_effect(cmd, **kwargs):
        flag = cmd[1]
        # everything supported except --mount
        return MagicMock(returncode=1 if flag == "--mount" else 0)

    mock_run.side_effect = side_effect
    missing = ns.probe_namespace_support()
    assert missing == ["--mount"]


@patch("chroot_distro.helpers.namespace._resolve_unshare", side_effect=ns.NamespaceError("no unshare"))
def test_probe_namespace_support_no_unshare_reports_all(_unshare):
    # The strict pre-check covers only the required namespaces, so when
    # unshare is missing it reports the whole required set as unavailable.
    assert ns.probe_namespace_support() == list(ns._REQUIRED_PROBE_FLAGS)


# ---------------------------------------------------------------------------
# CD_USE_NS environment detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "on", "  on  "])
def test_use_ns_env_enabled_truthy(value):
    with patch.dict("os.environ", {"CD_USE_NS": value}, clear=True):
        assert ns.use_ns_env_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "random"])
def test_use_ns_env_enabled_falsy(value):
    with patch.dict("os.environ", {"CD_USE_NS": value}, clear=True):
        assert ns.use_ns_env_enabled() is False


def test_use_ns_env_enabled_unset():
    with patch.dict("os.environ", {}, clear=True):
        assert ns.use_ns_env_enabled() is False


def test_should_use_namespaces_isolated_flag_without_env():
    with patch.dict("os.environ", {}, clear=True):
        assert ns.should_use_namespaces(True) is True
        assert ns.should_use_namespaces(False) is False


def test_should_use_namespaces_env_enables_without_flag():
    with patch.dict("os.environ", {"CD_USE_NS": "1"}, clear=True):
        # CD_USE_NS turns on namespaces even when --isolated was not passed.
        assert ns.should_use_namespaces(False) is True


# ---------------------------------------------------------------------------
# Opportunistic cgroup namespace probing
# ---------------------------------------------------------------------------


def test_cgroup_in_probe_flags_but_not_required_set():
    assert "--cgroup" in ns._PROBE_FLAGS
    assert "--cgroup" not in ns._REQUIRED_PROBE_FLAGS
    # nsenter short-flag translation must know about cgroup.
    assert ns._LONG_TO_SHORT["--cgroup"] == "-C"


@patch("chroot_distro.helpers.namespace._resolve_unshare", return_value="unshare")
@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_unshare_flags_includes_cgroup_when_supported(mock_run, _unshare):
    mock_run.return_value = MagicMock(returncode=0)
    flags = ns.probe_unshare_flags()
    assert "--cgroup" in flags
    for required in ns._REQUIRED_PROBE_FLAGS:
        assert required in flags


@patch("chroot_distro.helpers.namespace._resolve_unshare", return_value="unshare")
@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_unshare_flags_drops_cgroup_when_unsupported(mock_run, _unshare):
    # cgroup unshare fails (e.g. Android kernel without cgroupns); the rest
    # succeed. cgroup must be dropped while the required set is kept.
    def side_effect(cmd, **kwargs):
        flag = cmd[1]
        return MagicMock(returncode=1 if flag == "--cgroup" else 0)

    mock_run.side_effect = side_effect
    flags = ns.probe_unshare_flags()
    assert "--cgroup" not in flags
    for required in ns._REQUIRED_PROBE_FLAGS:
        assert required in flags


@patch("chroot_distro.helpers.namespace._resolve_unshare", return_value="unshare")
@patch("chroot_distro.helpers.namespace.subprocess.run")
def test_probe_namespace_support_ignores_missing_cgroup(mock_run, _unshare):
    # Strict pre-check only covers the required set, so a kernel missing only
    # cgroupns reports no missing required namespaces (no host fallback).
    def side_effect(cmd, **kwargs):
        flag = cmd[1]
        return MagicMock(returncode=1 if flag == "--cgroup" else 0)

    mock_run.side_effect = side_effect
    assert ns.probe_namespace_support() == []


def test_long_flags_to_nsenter_translates_cgroup():
    flags = ["--mount", "--pid", "--cgroup"]
    assert ns.long_flags_to_nsenter(flags, use_long=False) == ["-m", "-p", "-C"]
    assert ns.long_flags_to_nsenter(flags, use_long=True) == flags


def test_set_namespace_hostname_skips_without_uts():
    holder = MagicMock(container_name="alpine")
    with patch.object(ns, "_read_holder_flags", return_value=["--mount", "--pid"]):
        assert ns.set_namespace_hostname(holder, "alpine") is False
    holder.run.assert_not_called()


def test_set_namespace_hostname_uses_hostname_binary():
    holder = MagicMock(container_name="alpine")
    holder.run.return_value = MagicMock(returncode=0, stderr="")
    with patch.object(ns, "_read_holder_flags", return_value=["--mount", "--uts"]):
        assert ns.set_namespace_hostname(holder, "alpine") is True
    assert holder.run.call_args_list[0].args[0] == ["hostname", "alpine"]


def test_set_namespace_hostname_falls_back_to_proc():
    holder = MagicMock(container_name="alpine")

    def run(cmd, **kwargs):
        rc = 0 if cmd[0] == "sh" else 1
        return MagicMock(returncode=rc, stderr="not found")

    holder.run.side_effect = run
    with patch.object(ns, "_read_holder_flags", return_value=["--uts"]):
        assert ns.set_namespace_hostname(holder, "alpine") is True


def test_make_mount_private_falls_back_when_rprivate_rejected():
    """Android kernels reject --make-rprivate /; fall back to --make-private."""
    holder = MagicMock()

    def run(cmd, **kwargs):
        propagation = cmd[1]
        rc = 0 if propagation == "--make-private" else 1
        return MagicMock(returncode=rc, stderr="Operation not permitted")

    holder.run.side_effect = run
    assert ns.make_mount_private(holder) is True
    attempted = [call.args[0][1] for call in holder.run.call_args_list]
    assert attempted[0] == "--make-rprivate"
    assert "--make-private" in attempted


def test_make_mount_private_returns_false_when_all_fail():
    holder = MagicMock()
    holder.run.return_value = MagicMock(returncode=1, stderr="Operation not permitted")
    assert ns.make_mount_private(holder) is False
    attempted = [call.args[0][1] for call in holder.run.call_args_list]
    assert attempted == ["--make-rprivate", "--make-private", "--make-rslave"]


def test_check_isolation_conflicts_namespace_mode_without_flag():
    with (
        patch.object(ns, "get_live_holder", return_value=MagicMock(pid=1)),
        patch.object(ns, "read_isolation_mode", return_value=ns.ISOLATION_MODE_NAMESPACE),
        pytest.raises(ns.NamespaceError, match="isolated namespace mode"),
    ):
        ns.check_isolation_conflicts(
            "alpine",
            use_namespaces=False,
            host_mounts_exist=False,
        )


def test_check_isolation_conflicts_host_mounts_with_isolated():
    with (
        patch.object(ns, "get_live_holder", return_value=None),
        patch.object(ns, "read_isolation_mode", return_value=ns.ISOLATION_MODE_HOST),
        pytest.raises(ns.NamespaceError, match="host mount namespace"),
    ):
        ns.check_isolation_conflicts(
            "alpine",
            use_namespaces=True,
            host_mounts_exist=True,
        )


@patch("chroot_distro.helpers.namespace._pid_alive", return_value=True)
@patch("chroot_distro.helpers.namespace._read_holder_flags", return_value=["--mount"])
@patch("chroot_distro.helpers.namespace._read_holder_pid", return_value=42)
@patch("chroot_distro.helpers.namespace._nsenter_supports_long_flags", return_value=True)
def test_get_live_holder(*_mocks):
    holder = ns.get_live_holder("alpine")
    assert holder is not None
    assert holder.pid == 42
    assert holder.run_argv(["echo", "hi"])[0].endswith("nsenter")


@patch("chroot_distro.helpers.namespace.get_live_holder")
@patch("chroot_distro.helpers.namespace._create_holder")
@patch("chroot_distro.helpers.namespace.probe_unshare_flags", return_value=["--mount"])
def test_acquire_holder_reuses_existing(mock_probe, mock_create, mock_get):
    existing = MagicMock(pid=99)
    mock_get.return_value = existing
    assert ns.acquire_holder("alpine") is existing
    mock_create.assert_not_called()
    mock_probe.assert_not_called()


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace._read_holder_pid", return_value=100)
@patch("chroot_distro.helpers.namespace.os.kill")
def test_release_holder(mock_kill, *_mocks):
    ns.release_holder("alpine")
    assert mock_kill.called


def test_get_process_start_time():
    with patch("chroot_distro.helpers.namespace.os.stat") as mock_stat:
        mock_stat.return_value = MagicMock(st_mtime=12345.67)
        assert ns._get_process_start_time(42) == 12345.67

    with patch("chroot_distro.helpers.namespace.os.stat", side_effect=OSError):
        assert ns._get_process_start_time(42) is None


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace.os.path.isfile", return_value=True)
def test_read_holder_pid_success(mock_isfile, mock_remove_state):
    patch("builtins.open", mock_open(read_data="42\n12345.67\n")).start()
    try:
        with (
            patch("chroot_distro.helpers.namespace._pid_alive", return_value=True),
            patch("chroot_distro.helpers.namespace._is_sleep_infinity_holder", return_value=True),
            patch("chroot_distro.helpers.namespace._get_process_start_time", return_value=12345.67),
        ):
            assert ns._read_holder_pid("alpine") == 42
            mock_remove_state.assert_not_called()
    finally:
        patch.stopall()


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace.os.path.isfile", return_value=True)
def test_read_holder_pid_stale_start_time(mock_isfile, mock_remove_state):
    patch("builtins.open", mock_open(read_data="42\n12345.67\n")).start()
    try:
        with (
            patch("chroot_distro.helpers.namespace._pid_alive", return_value=True),
            patch("chroot_distro.helpers.namespace._is_sleep_infinity_holder", return_value=True),
            patch("chroot_distro.helpers.namespace._get_process_start_time", return_value=99999.99),
        ):
            assert ns._read_holder_pid("alpine") is None
            mock_remove_state.assert_called_once_with("alpine")
    finally:
        patch.stopall()


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace.os.path.isfile", return_value=True)
def test_read_holder_pid_dead_process(mock_isfile, mock_remove_state):
    patch("builtins.open", mock_open(read_data="42\n12345.67\n")).start()
    try:
        with (
            patch("chroot_distro.helpers.namespace._pid_alive", return_value=False),
        ):
            assert ns._read_holder_pid("alpine") is None
            mock_remove_state.assert_called_once_with("alpine")
    finally:
        patch.stopall()


@patch("chroot_distro.helpers.namespace.subprocess.Popen")
@patch("chroot_distro.helpers.namespace._pick_new_holder_pid", return_value=None)
@patch("chroot_distro.helpers.namespace._remove_holder_state")
def test_create_holder_fails_and_cleans_up(mock_remove_state, mock_pick, mock_popen):
    mock_proc = MagicMock()
    mock_popen.return_value = mock_proc

    with pytest.raises(ns.NamespaceError, match="Failed to create the isolation namespace holder"):
        ns._create_holder("alpine", ["--mount"])

    mock_proc.kill.assert_called_once()
    mock_remove_state.assert_called()


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace._read_holder_pid", return_value=100)
@patch("chroot_distro.helpers.namespace.os.kill", side_effect=OSError("Permission denied"))
def test_release_holder_exception_safety(mock_kill, mock_read, mock_remove_state):
    ns.release_holder("alpine")
    mock_remove_state.assert_called_once_with("alpine")


@patch("chroot_distro.helpers.namespace.subprocess.Popen")
@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace._get_process_start_time", return_value=12345.67)
@patch("chroot_distro.helpers.namespace._read_host_child_pids", return_value=[555])
@patch("chroot_distro.helpers.namespace._nsenter_supports_long_flags", return_value=True)
def test_create_holder_with_custom_cmd(mock_nsenter, mock_read_child, mock_start, mock_remove, mock_popen):
    mock_proc = MagicMock(pid=444)
    mock_popen.return_value = mock_proc

    m_open = mock_open()
    with patch("builtins.open", m_open):
        holder = ns._create_holder("alpine", ["--mount", "--pid"], holder_cmd=["chroot", "rootfs", "/init"], pipe_r=3)

    assert holder.pid == 555
    assert holder.proc == mock_proc
    pid_file_call = [c for c in m_open.mock_calls if "holder.pid" in str(c)]
    assert pid_file_call


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace.os.path.isfile", return_value=True)
def test_read_holder_pid_custom_success(mock_isfile, mock_remove_state):
    patch("builtins.open", mock_open(read_data="42\n12345.67\ncustom\n")).start()
    try:
        with (
            patch("chroot_distro.helpers.namespace._pid_alive", return_value=True),
            patch("chroot_distro.helpers.namespace._is_sleep_infinity_holder", return_value=False),
            patch("chroot_distro.helpers.namespace._get_process_start_time", return_value=12345.67),
        ):
            assert ns._read_holder_pid("alpine") == 42
            mock_remove_state.assert_not_called()
    finally:
        patch.stopall()

