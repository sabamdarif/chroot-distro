import io
import json
import os
from unittest.mock import patch

from chroot_distro.commands.install import _print_start_hints, _run_install


def _spare_fd(*args, **kwargs):
    """A closable descriptor standing in for the rootfs install writes into."""
    return os.open(os.devnull, os.O_RDONLY)


def _spare_atomic_write(*args, **kwargs):
    """A context manager standing in for the staged manifest write."""
    return io.StringIO()


@patch(
    "chroot_distro.commands.install.pull_image",
    return_value={
        "image_ref": "alpine:latest",
        "arch": "x86_64",
        "manifest": {},
        "image_config": {},
    },
)
@patch("chroot_distro.commands.install.atomic_write", side_effect=_spare_atomic_write)
@patch("chroot_distro.commands.install.open_container_rootfs", side_effect=_spare_fd)
@patch("chroot_distro.commands.install._write_incomplete_marker")
@patch("chroot_distro.commands.install.os.makedirs")
@patch("chroot_distro.commands.install.os.path.isdir", return_value=False)
@patch("chroot_distro.commands.install.ContainerLock")
@patch("chroot_distro.commands.install.log_info")
def test_run_install_workers_log(
    mock_log, mock_lock, mock_isdir, mock_makedirs, mock_marker, mock_rootfs_fd, mock_atomic, mock_pull_image
):
    # Case 1: Workers is default (4), should not print workers info
    with patch("chroot_distro.commands.install.layer_download_workers", return_value=4):
        _run_install("my-container", "alpine", None, None, "x86_64")

        # Verify it printed the standard installing message
        mock_log.assert_any_call("Installing 'alpine:latest' as 'my-container'...")
        # Verify it did not print "Parallel download workers: ..."
        for call_args in mock_log.call_args_list:
            assert "Parallel download workers" not in call_args[0][0]

    # Case 2: Workers is non-default (6), should print workers info
    mock_log.reset_mock()
    with patch("chroot_distro.commands.install.layer_download_workers", return_value=6):
        _run_install("my-container", "alpine", None, None, "x86_64")

        # Verify it printed the standard installing message
        mock_log.assert_any_call("Installing 'alpine:latest' as 'my-container'...")
        # Verify it printed "Parallel download workers: 6"
        mock_log.assert_any_call("Parallel download workers: 6")


def _installed_tree(tmp_path, *, shell: bool, entrypoint=None, cmd=None):
    """A container directory holding a rootfs and a manifest.json."""
    container = tmp_path / "c"
    rootfs = container / "rootfs"
    rootfs.mkdir(parents=True)
    if shell:
        (rootfs / "bin").mkdir()
        (rootfs / "bin" / "sh").write_text("")
    config = {}
    if entrypoint is not None:
        config["Entrypoint"] = entrypoint
    if cmd is not None:
        config["Cmd"] = cmd
    (container / "manifest.json").write_text(json.dumps({"image_config": {"config": config}}))
    return str(container), str(rootfs)


def test_start_hints_skip_login_when_the_rootfs_has_no_shell(tmp_path, capsys):
    # hello-world: an Entrypoint and nothing login could exec.
    container, rootfs = _installed_tree(tmp_path, shell=False, entrypoint=["/hello"])

    _print_start_hints("hello-world", container, rootfs)

    err = capsys.readouterr().err
    assert "run hello-world" in err
    assert "login hello-world" not in err


def test_start_hints_offer_login_and_run_when_a_shell_exists(tmp_path, capsys):
    # alpine: a shell to log into, and a Cmd `run` can execute.
    container, rootfs = _installed_tree(tmp_path, shell=True, cmd=["/bin/sh"])

    _print_start_hints("alpine", container, rootfs)

    err = capsys.readouterr().err
    assert "login alpine" in err
    assert "run alpine" in err
