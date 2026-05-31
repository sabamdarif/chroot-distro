"""Unit tests for namespace isolation helpers."""

from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.helpers import namespace as ns


def test_long_flags_to_nsenter_short():
    flags = ["--mount", "--pid", "--uts", "--ipc"]
    assert ns.long_flags_to_nsenter(flags, use_long=False) == ["-m", "-p", "-u", "-i"]


def test_holder_unshare_argv_adds_fork_with_pid():
    argv = ns._holder_unshare_argv("unshare", ["--pid", "--mount"])
    assert argv == ["unshare", "--fork", "--pid", "--mount", "sleep", "infinity"]


def test_holder_unshare_argv_no_duplicate_fork():
    argv = ns._holder_unshare_argv("unshare", ["--fork", "--mount"])
    assert argv.count("--fork") == 1
    assert argv[-2:] == ["sleep", "infinity"]


def test_pick_new_holder_pid():
    before = {10, 20}
    with patch.object(ns, "_snapshot_sleep_infinity_pids", return_value={10, 20, 99}):
        assert ns._pick_new_holder_pid(before) == 99


def test_pick_new_holder_pid_from_launcher_child():
    before: set[int] = set()
    with (
        patch.object(ns, "_snapshot_sleep_infinity_pids", return_value=set()),
        patch.object(ns, "_read_host_child_pids", return_value=[12345]),
        patch.object(ns, "_is_sleep_infinity_holder", side_effect=lambda pid: pid == 12345),
    ):
        assert ns._pick_new_holder_pid(before, launcher_pid=999) == 12345


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
    assert holder.run_argv(["echo", "hi"])[0] == "nsenter"


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
