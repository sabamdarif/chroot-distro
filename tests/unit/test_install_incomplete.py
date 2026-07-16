"""Tests for the .install-incomplete marker: interrupted installs must be
detected and wiped on the next attempt instead of reported as 'already
exists', and a finished install must not carry the marker."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from chroot_distro.commands.install import _run_install
from chroot_distro.paths import container_incomplete_marker


@pytest.fixture
def containers(tmp_path):
    """Redirect container paths into tmp_path for _run_install."""
    with patch("chroot_distro.constants.CONTAINERS_DIR", str(tmp_path)):
        # paths.py reads CONTAINERS_DIR at call time via its own import;
        # patch the symbol it actually uses.
        with patch("chroot_distro.paths.CONTAINERS_DIR", str(tmp_path)):
            yield tmp_path


def _paths(tmp_path, name):
    cdir = tmp_path / name
    return cdir, cdir / "rootfs", cdir / ".install-incomplete"


@patch("chroot_distro.commands.install.pull_image", return_value=None)
@patch("chroot_distro.commands.install.log_info")
def test_successful_install_leaves_no_marker(mock_log, mock_pull, containers):
    cdir, rootfs, marker = _paths(containers, "alpine")
    _run_install("alpine", "alpine", None, None, "x86_64")
    assert rootfs.is_dir()
    assert not marker.exists()


@patch("chroot_distro.commands.install.pull_image", return_value=None)
@patch("chroot_distro.commands.install.log_info")
def test_marker_exists_while_install_runs(mock_log, mock_pull, containers):
    """The marker must be on disk before any rootfs content is written."""
    cdir, rootfs, marker = _paths(containers, "alpine")
    seen = {}

    def _pull(image_ref, rootfs_dir, arch, insecure=False):
        seen["marker_during_pull"] = marker.exists()
        return

    mock_pull.side_effect = _pull
    _run_install("alpine", "alpine", None, None, "x86_64")
    assert seen["marker_during_pull"] is True
    assert not marker.exists()


@patch("chroot_distro.commands.install.pull_image", return_value=None)
@patch("chroot_distro.commands.install.log_info")
def test_interrupted_leftover_is_wiped_and_reinstalled(mock_log, mock_pull, containers):
    """rootfs + marker = aborted install: wipe it and proceed, no error."""
    cdir, rootfs, marker = _paths(containers, "ubuntu")
    rootfs.mkdir(parents=True)
    (rootfs / "partial-layer-data").write_bytes(b"\x00" * 10)
    marker.touch()

    _run_install("ubuntu", "ubuntu", None, None, "x86_64")

    assert not marker.exists()
    assert not (rootfs / "partial-layer-data").exists()  # old remnants gone
    assert rootfs.is_dir()  # fresh install created a new rootfs
    mock_pull.assert_called_once()
    mock_log.assert_any_call("Found remnants of an interrupted install of 'ubuntu'; removing and reinstalling...")


@patch("chroot_distro.commands.install.pull_image", return_value=None)
@patch("chroot_distro.commands.install.log_info")
def test_completed_container_still_refuses_reinstall(mock_log, mock_pull, containers):
    """rootfs without marker = a real container: must still hard-refuse."""
    cdir, rootfs, marker = _paths(containers, "ubuntu")
    rootfs.mkdir(parents=True)

    with pytest.raises(SystemExit) as exc_info:
        _run_install("ubuntu", "ubuntu", None, None, "x86_64")
    assert exc_info.value.code == 1
    mock_pull.assert_not_called()
    assert rootfs.is_dir()  # untouched


@patch("chroot_distro.commands.install.pull_image", side_effect=RuntimeError("network died"))
@patch("chroot_distro.commands.install.log_info")
@patch("chroot_distro.commands.install.log_error")
def test_failed_install_cleanup_removes_marker_too(mock_err, mock_log, mock_pull, containers):
    """A failure that IS handled removes the whole container dir, marker included."""
    cdir, rootfs, marker = _paths(containers, "debian")
    with pytest.raises(SystemExit):
        _run_install("debian", "debian", None, None, "x86_64")
    assert not cdir.exists()


def test_container_incomplete_marker_path():
    path = container_incomplete_marker("ubuntu")
    assert path.endswith(os.path.join("ubuntu", ".install-incomplete"))
