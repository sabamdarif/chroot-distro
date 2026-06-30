"""Unit tests for native namespace isolation helpers."""

import os
import signal
from unittest.mock import MagicMock, mock_open, patch

import pytest

from chroot_distro.helpers import namespace as ns
from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUTS,
    MS_PRIVATE,
    MS_REC,
    MS_SLAVE,
)

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
        assert ns.should_use_namespaces(False) is True


# ---------------------------------------------------------------------------
# Namespace probing
# ---------------------------------------------------------------------------


@patch("chroot_distro.helpers.namespace._probe_ns_support")
def test_probe_unshare_flags_requires_mount(mock_probe):
    # If CLONE_NEWNS is not supported, it must raise NamespaceError.
    mock_probe.return_value = CLONE_NEWPID
    with pytest.raises(ns.NamespaceError, match="Mount namespace"):
        ns.probe_unshare_flags()

    # Otherwise it returns the supported mask.
    mock_probe.return_value = CLONE_NEWNS | CLONE_NEWPID
    assert ns.probe_unshare_flags() == CLONE_NEWNS | CLONE_NEWPID


@patch("chroot_distro.helpers.namespace._probe_ns_support")
def test_probe_namespace_support_reports_missing(mock_probe):
    # Mock probe to report CLONE_NEWNS and CLONE_NEWPID as supported,
    # but UTS and IPC as unsupported.
    mock_probe.return_value = CLONE_NEWNS | CLONE_NEWPID
    missing = ns.probe_namespace_support(ns._REQUIRED_PROBE_FLAGS)
    assert "--uts" in missing
    assert "--ipc" in missing
    assert "--mount" not in missing
    assert "--pid" not in missing


# ---------------------------------------------------------------------------
# Namespace helper operations
# ---------------------------------------------------------------------------


def test_set_namespace_hostname_skips_without_uts():
    holder = MagicMock(container_name="alpine")
    with patch("chroot_distro.helpers.namespace._read_holder_flags", return_value=CLONE_NEWNS | CLONE_NEWPID):
        assert ns.set_namespace_hostname(holder, "alpine") is False


@patch("chroot_distro.helpers.namespace.os.fork", return_value=9999)
@patch("chroot_distro.helpers.namespace.os.waitpid", return_value=(9999, 0))
def test_set_namespace_hostname_success(mock_waitpid, mock_fork):
    holder = MagicMock(container_name="alpine", pid=123)
    holder._live_ns_flags.return_value = CLONE_NEWUTS
    with patch("chroot_distro.helpers.namespace._read_holder_flags", return_value=CLONE_NEWUTS):
        assert ns.set_namespace_hostname(holder, "myhost") is True

    mock_fork.assert_called_once()
    mock_waitpid.assert_called_once_with(9999, 0)


def test_make_mount_private_success():
    holder = MagicMock()
    # It tries rprivate first.
    holder.do_set_propagation.return_value = None
    assert ns.make_mount_private(holder) is True
    holder.do_set_propagation.assert_called_once_with("/", MS_REC | MS_PRIVATE)


def test_make_mount_private_falls_back():
    holder = MagicMock()
    # First attempt (rprivate) fails, second (private) succeeds.
    holder.do_set_propagation.side_effect = [OSError("rprivate rejected"), None]
    assert ns.make_mount_private(holder) is True
    assert holder.do_set_propagation.call_count == 2


def test_make_mount_private_returns_false_when_all_fail():
    holder = MagicMock()
    holder.do_set_propagation.side_effect = OSError("failed")
    assert ns.make_mount_private(holder) is False


# ---------------------------------------------------------------------------
# Holder state and lifecycle
# ---------------------------------------------------------------------------


@patch("chroot_distro.helpers.namespace.filter_accessible_namespaces", return_value=CLONE_NEWNS)
@patch("chroot_distro.helpers.namespace._pid_alive", return_value=True)
@patch("chroot_distro.helpers.namespace._read_holder_flags", return_value=CLONE_NEWNS)
@patch("chroot_distro.helpers.namespace._read_holder_pid", return_value=42)
def test_get_live_holder(mock_read_pid, mock_read_flags, mock_alive, mock_filter):
    holder = ns.get_live_holder("alpine")
    assert holder is not None
    assert holder.pid == 42
    assert holder.ns_flags == CLONE_NEWNS


@patch("chroot_distro.helpers.namespace.get_live_holder")
@patch("chroot_distro.helpers.namespace._create_holder")
@patch("chroot_distro.helpers.namespace.probe_unshare_flags", return_value=CLONE_NEWNS)
def test_acquire_holder_reuses_existing(mock_probe, mock_create, mock_get):
    existing = MagicMock(pid=99)
    mock_get.return_value = existing
    assert ns.acquire_holder("alpine") is existing
    mock_create.assert_not_called()


@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace._read_holder_pid", return_value=100)
@patch("chroot_distro.helpers.namespace.os.kill")
def test_release_holder(mock_kill, mock_read, mock_remove):
    ns.release_holder("alpine")
    mock_kill.assert_any_call(100, signal.SIGTERM)
    mock_remove.assert_called_once_with("alpine")


@patch("chroot_distro.helpers.namespace.create_holder_process")
@patch("chroot_distro.helpers.namespace.filter_accessible_namespaces")
@patch("chroot_distro.helpers.namespace._remove_holder_state")
@patch("chroot_distro.helpers.namespace._pid_alive", return_value=True)
def test_create_holder_success(mock_alive, mock_remove, mock_filter, mock_create):
    mock_create.return_value = 555
    mock_filter.return_value = CLONE_NEWNS | CLONE_NEWPID

    m_open = mock_open()
    with (
        patch("builtins.open", m_open),
        patch("chroot_distro.helpers.namespace._get_process_start_time", return_value=12345.67),
    ):
        holder = ns._create_holder("alpine", CLONE_NEWNS | CLONE_NEWPID, rootfs="/tmp/rootfs")

    assert holder.pid == 555
    assert holder.ns_flags == CLONE_NEWNS | CLONE_NEWPID
    mock_create.assert_called_once_with(CLONE_NEWNS | CLONE_NEWPID, rootfs="/tmp/rootfs")
