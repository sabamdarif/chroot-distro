import json
import os
from types import SimpleNamespace

import pytest

import chroot_distro.commands.run as run_mod
from chroot_distro.commands.run import _normalize_argv, _string_field, command_run

# ---------------------------------------------------------------------------
# _normalize_argv — shell-form guard, and the shapes a manifest may not hold
# ---------------------------------------------------------------------------


def test_normalize_argv_json_array():
    argv, is_shell = _normalize_argv(["/bin/echo", "hi"], "Cmd", "t")
    assert argv == ["/bin/echo", "hi"]
    assert is_shell is False


def test_normalize_argv_shell_form_string():
    # A shell-form (string) value must NOT be character-split by list().
    argv, is_shell = _normalize_argv("echo hi && ls", "Cmd", "t")
    assert argv == ["/bin/sh", "-c", "echo hi && ls"]
    assert is_shell is True


@pytest.mark.parametrize("val", [None, [], ""])
def test_normalize_argv_empty(val):
    argv, is_shell = _normalize_argv(val, "Cmd", "t")
    assert argv == []
    assert is_shell is False


@pytest.mark.parametrize("val", [0, 5, True, {"a": 1}, ["/bin/echo", 42], ["ok", None]])
def test_normalize_argv_refuses_a_shape_no_argv_can_be_built_from(val, capsys):
    # Coercing each item with str() invented an argv out of whatever JSON held,
    # and dropping the field quietly ran a different command than the image names.
    with pytest.raises(SystemExit) as exc:
        _normalize_argv(val, "Entrypoint", "t")
    assert exc.value.code == 1
    assert "Entrypoint" in capsys.readouterr().err


def test_string_field_reads_what_is_set_and_refuses_the_rest(capsys):
    assert _string_field({"WorkingDir": "/srv"}, "WorkingDir", "t") == "/srv"
    assert _string_field({}, "WorkingDir", "t") == ""
    assert _string_field({"WorkingDir": None}, "WorkingDir", "t") == ""
    with pytest.raises(SystemExit):
        _string_field({"WorkingDir": 5}, "WorkingDir", "t")
    assert "WorkingDir" in capsys.readouterr().err


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


# ---------------------------------------------------------------------------
# The manifest is a registry's JSON, kept verbatim by install, in a file that
# sits under the bound $TERMUX_PREFIX on Termux. What it says about the command
# to run is checked against the shape OCI gives it, and a refusal is a message.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "config",
    [
        {"Entrypoint": 5, "Cmd": ["/bin/sh"]},
        {"Cmd": {"/bin/sh": {}}},
        {"Cmd": ["/bin/sh", 5]},
        {"Cmd": ["/bin/sh"], "WorkingDir": ["/app"]},
        {"Cmd": ["/bin/sh"], "User": 1000},
    ],
)
def test_a_malformed_field_is_refused_rather_than_dropped(captured_run, config, monkeypatch, capsys):
    monkeypatch.delenv("CD_USER", raising=False)
    monkeypatch.delenv("CD_WORKDIR", raising=False)
    with pytest.raises(SystemExit) as exc:
        captured_run(config)
    assert exc.value.code == 1
    assert "malformed" in capsys.readouterr().err
