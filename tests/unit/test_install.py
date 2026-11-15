import json
from unittest.mock import Mock

import pytest

from chroot_distro.commands.install import _print_start_hints, _run_install


@pytest.mark.parametrize("workers", [4, 6])
def test_run_install_workers_log(tmp_path, monkeypatch, workers):
    from chroot_distro.commands import install

    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(tmp_path / "containers"))
    monkeypatch.setattr(install, "BASE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(install, "pull_image", Mock(return_value=None))
    monkeypatch.setattr(install, "layer_download_workers", lambda: workers)
    log = Mock()
    monkeypatch.setattr(install, "log_info", log)
    _run_install("my-container", "alpine", None, None, "x86_64")
    log.assert_any_call("Installing 'alpine:latest' as 'my-container'...")
    worker_lines = [call.args[0] for call in log.call_args_list if "Parallel download workers" in call.args[0]]
    assert worker_lines == ([] if workers == 4 else ["Parallel download workers: 6"])


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
