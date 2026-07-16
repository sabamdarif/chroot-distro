import json
import os
from types import SimpleNamespace

import pytest

import chroot_distro.commands.run as run_mod
from chroot_distro.commands.run import _normalize_argv, command_run

# ---------------------------------------------------------------------------
# _normalize_argv — shell-form guard
# ---------------------------------------------------------------------------


def test_normalize_argv_json_array():
    argv, is_shell = _normalize_argv(["/bin/echo", "hi"])
    assert argv == ["/bin/echo", "hi"]
    assert is_shell is False


def test_normalize_argv_coerces_non_str_elements():
    argv, is_shell = _normalize_argv(["/bin/echo", 42])
    assert argv == ["/bin/echo", "42"]
    assert is_shell is False


def test_normalize_argv_shell_form_string():
    # A shell-form (string) value must NOT be character-split by list().
    argv, is_shell = _normalize_argv("echo hi && ls")
    assert argv == ["/bin/sh", "-c", "echo hi && ls"]
    assert is_shell is True


@pytest.mark.parametrize("val", [None, [], "", 0])
def test_normalize_argv_empty(val):
    argv, is_shell = _normalize_argv(val)
    assert argv == []
    assert is_shell is False


# ---------------------------------------------------------------------------
# command_run — argv resolution + override precedence
#
# command_run hands off to command_login; we patch that out and capture the
# resolved args so the pure resolution logic can be asserted in isolation.
# ---------------------------------------------------------------------------


def _write_manifest(tmp_path, config):
    """Create a container dir with a manifest.json holding image_config.config."""
    name = "t"
    container = tmp_path / "containers" / name
    (container / "rootfs").mkdir(parents=True)
    manifest = {"image_config": {"config": config}}
    (container / "manifest.json").write_text(json.dumps(manifest))
    return name, str(container)


@pytest.fixture
def captured_run(tmp_path, monkeypatch):
    """Run command_run against a temp manifest and capture the handoff args.

    Returns a callable ``run(config, **arg_overrides)`` -> captured args.
    """
    captured = {}

    def fake_login(args):
        captured["args"] = args

    monkeypatch.setattr(run_mod, "command_login", fake_login)

    def run(config, **arg_overrides):
        name, container = _write_manifest(tmp_path, config)
        monkeypatch.setattr(run_mod, "container_rootfs", lambda n: os.path.join(container, "rootfs"))
        monkeypatch.setattr(run_mod, "container_manifest", lambda n: os.path.join(container, "manifest.json"))
        args = SimpleNamespace(
            container_name=name,
            run_args=[],
            user=None,
            work_dir=None,
            entrypoint=None,
        )
        for k, v in arg_overrides.items():
            setattr(args, k, v)
        command_run(args)
        return captured["args"]

    return run


def test_entrypoint_plus_cmd(captured_run):
    args = captured_run({"Entrypoint": ["/bin/ep"], "Cmd": ["a", "b"]})
    assert args._run_inner == ["/bin/ep", "a", "b"]


def test_trailing_args_replace_cmd(captured_run):
    args = captured_run({"Entrypoint": ["/bin/ep"], "Cmd": ["a", "b"]}, run_args=["x", "y"])
    assert args._run_inner == ["/bin/ep", "x", "y"]


def test_only_cmd(captured_run):
    args = captured_run({"Cmd": ["/bin/sh"]})
    assert args._run_inner == ["/bin/sh"]


def test_shell_form_entrypoint_ignores_cmd(captured_run):
    args = captured_run({"Entrypoint": "echo hi", "Cmd": ["ignored"]})
    assert args._run_inner == ["/bin/sh", "-c", "echo hi"]


def test_entrypoint_override_flag_clears_cmd(captured_run):
    args = captured_run({"Entrypoint": ["/bin/ep"], "Cmd": ["a"]}, entrypoint="/bin/echo")
    assert args._run_inner == ["/bin/echo"]


def test_entrypoint_override_with_trailing_args(captured_run):
    args = captured_run(
        {"Entrypoint": ["/bin/ep"], "Cmd": ["a"]},
        entrypoint="/bin/echo",
        run_args=["override"],
    )
    assert args._run_inner == ["/bin/echo", "override"]


def test_neither_entrypoint_nor_cmd_errors(captured_run):
    with pytest.raises(SystemExit):
        captured_run({})


# ---------------------------------------------------------------------------
# CD_* precedence: CLI flag > CD_* env > image config default
# ---------------------------------------------------------------------------


def test_cd_entrypoint_env_used_when_no_flag(captured_run, monkeypatch):
    monkeypatch.setenv("CD_ENTRYPOINT", "/bin/from-env")
    args = captured_run({"Entrypoint": ["/bin/ep"]})
    assert args._run_inner == ["/bin/from-env"]


def test_flag_beats_cd_entrypoint_env(captured_run, monkeypatch):
    monkeypatch.setenv("CD_ENTRYPOINT", "/bin/from-env")
    args = captured_run({"Entrypoint": ["/bin/ep"]}, entrypoint="/bin/from-flag")
    assert args._run_inner == ["/bin/from-flag"]


def test_cd_user_env_used_when_no_flag(captured_run, monkeypatch):
    monkeypatch.setenv("CD_USER", "envuser")
    args = captured_run({"Cmd": ["/bin/sh"], "User": "imguser"})
    assert args.user == "envuser"


def test_flag_beats_cd_user_and_image(captured_run, monkeypatch):
    monkeypatch.setenv("CD_USER", "envuser")
    args = captured_run({"Cmd": ["/bin/sh"], "User": "imguser"}, user="flaguser")
    assert args.user == "flaguser"


def test_image_user_used_when_no_flag_or_env(captured_run, monkeypatch):
    monkeypatch.delenv("CD_USER", raising=False)
    args = captured_run({"Cmd": ["/bin/sh"], "User": "imguser"})
    assert args.user == "imguser"


def test_cd_workdir_env_beats_image_workingdir(captured_run, monkeypatch):
    monkeypatch.setenv("CD_WORKDIR", "/from-env")
    args = captured_run({"Cmd": ["/bin/sh"], "WorkingDir": "/app"})
    assert args.work_dir == "/from-env"


def test_flag_beats_cd_workdir(captured_run, monkeypatch):
    monkeypatch.setenv("CD_WORKDIR", "/from-env")
    args = captured_run({"Cmd": ["/bin/sh"], "WorkingDir": "/app"}, work_dir="/from-flag")
    assert args.work_dir == "/from-flag"


def test_image_workingdir_used_when_no_flag_or_env(captured_run, monkeypatch):
    monkeypatch.delenv("CD_WORKDIR", raising=False)
    args = captured_run({"Cmd": ["/bin/sh"], "WorkingDir": "/app"})
    assert args.work_dir == "/app"
