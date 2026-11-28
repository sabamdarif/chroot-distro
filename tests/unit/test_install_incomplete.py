"""Tests for the .install-incomplete marker: interrupted installs must be
detected and wiped on the next attempt instead of reported as 'already
exists', and a finished install must not carry the marker."""

from __future__ import annotations

import json
import os
import tarfile
import urllib.error
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chroot_distro.commands.install import _run_install
from chroot_distro.commands import install, reset
from chroot_distro.helpers import download
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


def test_truncated_plain_archive_does_not_complete_install(containers, capsys):
    archive = containers / "archive.tar"
    directory = tarfile.TarInfo("etc")
    directory.type = tarfile.DIRTYPE
    archive.write_bytes(directory.tobuf())

    with pytest.raises(SystemExit) as exc:
        _run_install("box", str(archive), str(archive), None, "x86_64")

    _, rootfs, marker = _paths(containers, "box")
    assert exc.value.code == 1
    assert "invalid tar header or terminator" in capsys.readouterr().err
    assert marker.is_file()
    assert not list(rootfs.iterdir())


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
def test_failed_install_retains_marked_payload(mock_err, mock_log, mock_pull, containers):
    """Handled failures retain the marker for automatic retry."""
    cdir, rootfs, marker = _paths(containers, "debian")
    with pytest.raises(SystemExit):
        _run_install("debian", "debian", None, None, "x86_64")
    assert rootfs.is_dir()
    assert marker.is_file()


def test_container_incomplete_marker_path():
    path = container_incomplete_marker("ubuntu")
    assert path.endswith(os.path.join("ubuntu", ".install-incomplete"))


def test_install_url_diagnostics_keep_request_credentials_private(containers, monkeypatch, capsys):
    url = "https://user:password@example.com/archive.tar?token=secret#fragment"
    monkeypatch.setattr(install, "BASE_CACHE_DIR", str(containers / "cache"))
    monkeypatch.setattr("chroot_distro.constants.layer_download_workers", lambda: 1)
    monkeypatch.setattr(download, "_get_max_retries", lambda: 1)
    monkeypatch.setattr(download, "_get_retry_delays", lambda _: (0,))

    def open_response(req, **_):
        assert req.full_url == url
        raise urllib.error.HTTPError(url, 503, f"Echoed {url}", {}, None)

    monkeypatch.setattr(download, "http_opener", lambda **_: SimpleNamespace(open=open_response))

    with pytest.raises(SystemExit):
        _run_install("box", url, None, url, "x86_64")

    error = capsys.readouterr().err
    assert "Retry 1/1 in 0s (HTTP 503)" in error
    assert "Failed to install: Cannot download from 'https://example.com': HTTP 503" in error
    assert all(value not in error for value in ("user:", "password", "archive.tar", "secret", "fragment"))


@pytest.mark.parametrize("metadata", [
    {"image_ref": "https://user:password@example.com/archive.tar?token=secret#fragment"},
    {"image_ref": ""},
    {"image_ref": "image@sha256:" + "a" * 64},
    {"image_ref": "example.com/image:stable", "arch": ["amd64"]},
    [],
])
def test_reset_refuses_invalid_source_before_teardown(containers, monkeypatch, capsys, metadata):
    container, rootfs, _ = _paths(containers, "box")
    rootfs.mkdir(parents=True)
    (container / "manifest.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(reset, "ContainerLock", lambda *args, **kwargs: nullcontext())

    def unexpected(*args):
        pytest.fail("reset must validate its source before teardown")

    monkeypatch.setattr(reset.session, "get_active_chroot_pids", unexpected)
    with pytest.raises(SystemExit, match="1"):
        reset.command_reset(SimpleNamespace(container_name="box"))

    error = capsys.readouterr().err
    assert "for reset" in error
    assert all(part not in error for part in ("password", "secret", "fragment"))
    assert rootfs.is_dir()


def test_reset_uses_registry_path_for_archive_suffixed_tag(containers, monkeypatch):
    container, rootfs, _ = _paths(containers, "box")
    rootfs.mkdir(parents=True)
    ref = "example.com/image:release.tar"
    (container / "manifest.json").write_text(json.dumps({"image_ref": ref, "arch": "linux/amd64"}))
    monkeypatch.setattr(reset, "ContainerLock", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(reset.session, "get_active_chroot_pids", lambda _: [])
    monkeypatch.setattr(reset.mount_manager, "ensure_no_mounts", lambda _: None)
    monkeypatch.setattr(install, "BASE_CACHE_DIR", str(containers / "cache"))
    monkeypatch.setattr(install, "IS_TERMUX", False)
    with patch.object(install, "pull_image", return_value=None) as pull:
        reset.command_reset(SimpleNamespace(container_name="box"))

    pull.assert_called_once()
    assert pull.call_args.args[0] == ref
    assert pull.call_args.args[2].architecture == "amd64"
    assert rootfs.is_dir()
