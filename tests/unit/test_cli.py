import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.cli import _ensure_root_user, main
from chroot_distro.exceptions import ChrootDistroError, RootRequiredError


def test_ensure_root_user():
    # As non-root, it should call elevate_or_die
    with patch("os.geteuid", return_value=1000), patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
        _ensure_root_user()
        mock_elevate.assert_called_once()

    # As root, it should pass without raising and not call elevate_or_die
    with (
        patch("os.getuid", return_value=1000),
        patch("os.geteuid", return_value=0),
        patch("chroot_distro.elevate.elevate_or_die") as mock_elevate,
    ):
        _ensure_root_user()
        mock_elevate.assert_not_called()


def test_main_help():
    # Running with no args or --help should trigger command_help and exit 0
    with patch("sys.argv", ["chroot-distro"]), patch("chroot_distro.commands.help.command_help") as mock_help:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_help.assert_called_once()

    with patch("sys.argv", ["chroot-distro", "--help"]), patch("chroot_distro.commands.help.command_help") as mock_help:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_help.assert_called_once()


@pytest.mark.parametrize(
    ("arguments", "usage"),
    [
        (["help"], "chroot-distro [COMMAND]"),
        (["help", "info"], "chroot-distro info"),
        (["he", "ls"], "chroot-distro list"),
        (["help", "help"], "chroot-distro help [COMMAND]"),
        (["h", "nf"], "chroot-distro info"),
        (["--", "help", "info"], "chroot-distro info"),
    ],
)
def test_main_help_topic(arguments, usage, capsys):
    with (
        patch("sys.argv", ["chroot-distro", *arguments]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
    ):
        main()

    ensure_root.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert usage in captured.err
    assert ("QUICK START" in captured.err) == (arguments == ["help"])


@pytest.mark.parametrize(
    ("arguments", "diagnostic"),
    [
        (["bad\x1b[2J\n"], r"unknown command 'bad\x1b[2J\n'."),
        (["--bad\x1b[2J"], r"unknown command '--bad\x1b[2J'."),
        (["remove", "--bad\x1b[2J"], r"unrecognized option: '--bad\x1b[2J'."),
        (["diff", "box", "bad\x9b\u202e"], r"unexpected argument: 'bad\x9b\u202e'."),
        (["help", "bad\x1b[2J\u202e"], r"unknown help topic 'bad\x1b[2J\u202e'."),
        (["help", ""], "unknown help topic ''."),
        (["help", "info", "ls"], "unexpected argument: 'ls'."),
        (["build", "--c=\x1b[2J\x9b\u202e"], r"ambiguous option: --c=\e[2J\x9b\u202e"),
    ],
)
def test_main_quotes_rejected_arguments(arguments, diagnostic, capsys):
    with patch("sys.argv", ["chroot-distro", *arguments]), pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert diagnostic in captured.err
    assert not any(control in captured.err for control in ("\x1b", "\x9b", "\u202e"))


@pytest.mark.parametrize("command", ["login", "sh", "run"])
def test_main_requires_container_before_guest_arguments(command, capsys):
    with (
        patch("sys.argv", ["chroot-distro", command, "--", "box", "--help"]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    ensure_root.assert_not_called()
    assert "container name is not specified." in capsys.readouterr().err


def test_main_list():
    # Running list should call command_list
    mock_list = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "list"]),
        patch("os.geteuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}),
    ):
        main()
        mock_list.assert_called_once()


def test_main_login_requires_root():
    # Running login as non-root (UID 1000) should attempt privilege elevation
    # Mock elevate_or_die to raise RootRequiredError to simulate failed/disabled elevation
    with (
        patch("sys.argv", ["chroot-distro", "login", "alpine"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


@patch("chroot_distro.cli.IS_TERMUX", True)
def test_main_termux_list_does_not_require_root():
    # In Termux, 'list' does not require root
    mock_list = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "list"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die") as mock_elevate,
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}),
    ):
        main()
        mock_list.assert_called_once()
        mock_elevate.assert_not_called()


@patch("chroot_distro.cli.IS_TERMUX", False)
def test_main_linux_list_requires_root():
    # In normal Linux, 'list' requires root
    mock_list = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "list"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")) as mock_elevate,
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_elevate.assert_called_once()
        mock_list.assert_not_called()


def test_main_version():
    # Running with --version or -V should print version and exit 0
    with patch("sys.argv", ["chroot-distro", "--version"]), patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_print.assert_called_once()
        assert "chroot-distro" in mock_print.call_args[0][0]

    with patch("sys.argv", ["chroot-distro", "-V"]), patch("builtins.print") as mock_print:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_print.assert_called_once()
        assert "chroot-distro" in mock_print.call_args[0][0]


@patch("chroot_distro.cli.IS_TERMUX", True)
def test_main_termux_clears_preload():
    mock_list = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "list"]),
        patch("os.geteuid", return_value=1000),
        patch.dict("os.environ", {"LD_PRELOAD": "fake-preload", "LD_LIBRARY_PATH": "fake-libpath"}),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}),
    ):
        import os

        assert os.environ.get("LD_PRELOAD") == "fake-preload"
        assert os.environ.get("LD_LIBRARY_PATH") == "fake-libpath"
        main()
        assert "LD_PRELOAD" not in os.environ
        assert "LD_LIBRARY_PATH" not in os.environ


@patch("chroot_distro.cli.IS_TERMUX", True)
def test_main_termux_info_always_elevates():
    # 'info' is root-only on Termux too: its kernel probes need root.
    mock_info = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "info"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")) as mock_elevate,
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"info": mock_info}),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_elevate.assert_called_once()
        mock_info.assert_not_called()


@patch("chroot_distro.cli.IS_TERMUX", False)
def test_main_info_fails_when_root_is_unobtainable():
    # No rootless fallback: the command errors out instead of reporting less.
    mock_info = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", "info"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("no root here")),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"info": mock_info}),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_info.assert_not_called()


@patch("chroot_distro.cli.IS_TERMUX", False)
def test_main_linux_info_always_elevates():
    mock_info = MagicMock()
    # On Linux, info must elevate regardless of is_root_available
    with (
        patch("sys.argv", ["chroot-distro", "info"]),
        patch("os.geteuid", return_value=1000),
        patch("chroot_distro.elevate.elevate_or_die", side_effect=RootRequiredError("mock error")) as mock_elevate,
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"info": mock_info}),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        mock_elevate.assert_called_once()
        mock_info.assert_not_called()


def _finish(*_args, **_kwargs):
    from chroot_distro.exceptions import ChrootDistroError

    raise ChrootDistroError("container 'ghost' is not installed.")


def _assert_json_error(capsys, command, error):
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"command": command, "error": error, "schema": 1}
    assert error in captured.err


_PIPE_TEST_COMMANDS = """
import atexit
import sys
from chroot_distro import cli
from chroot_distro.commands import list_cmd, ps

def interrupt(_args):
    atexit.register(lambda: print("shutdown hook ran", file=sys.stderr))
    raise KeyboardInterrupt

cli._ensure_root_user = lambda: None
cli._COMMAND_HANDLERS["info"] = interrupt
list_cmd._iter_container_names = lambda: (["demo"], [])
ps.active_sessions = lambda: [{"pid": 42}]
ps.containers_with_active_pids = dict
cli.main()
"""


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX CLI signals and pipes")
@pytest.mark.parametrize("unbuffered", [False, True])
@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("-m", "chroot_distro", "--version"), id="version"),
        pytest.param(("-m", "chroot_distro", "--vers"), id="version-abbreviation"),
        pytest.param(("-m", "chroot_distro", "diff", "--json"), id="validation"),
        pytest.param(("-m", "chroot_distro", "ps", "--json", "--quiet"), id="parser"),
        pytest.param(("-c", _PIPE_TEST_COMMANDS, "ps", "--json"), id="json-result"),
        pytest.param(("-c", _PIPE_TEST_COMMANDS, "ps", "--quiet"), id="pids"),
        pytest.param(("-c", _PIPE_TEST_COMMANDS, "list", "--quiet"), id="names"),
        pytest.param(("-c", _PIPE_TEST_COMMANDS, "info", "--json"), id="interrupt"),
    ],
)
def test_cli_closed_stdout_pipe(arguments, unbuffered):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    env.pop("PYTHONUNBUFFERED", None)
    command = [sys.executable]
    if unbuffered:
        command.append("-u")
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    with os.fdopen(write_fd, "wb") as output:
        result = subprocess.run(
            [*command, *arguments], stdout=output, stderr=subprocess.PIPE, env=env, timeout=10
        )

    assert result.returncode == 1, result.stderr
    assert result.stderr == b""


def test_version_abbreviation_writes_to_stdout(capsys):
    with patch("sys.argv", ["chroot-distro", "--vers"]), pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out, err = capsys.readouterr()
    assert out.startswith("chroot-distro ")
    assert err == ""


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX descriptors")
@pytest.mark.parametrize(
    ("arguments", "status"),
    [
        (("-m", "chroot_distro", "--version"), 1),
        (("-m", "chroot_distro", "diff", "--json"), 1),
        (("-c", _PIPE_TEST_COMMANDS, "list", "--quiet"), 1),
        (("-c", _PIPE_TEST_COMMANDS, "ps", "--quiet"), 1),
        (("-c", _PIPE_TEST_COMMANDS, "info", "--json"), 1),
        (("-m", "chroot_distro", "--help"), 0),
    ],
)
def test_cli_absent_stdout(arguments, status):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    result = subprocess.run(
        [sys.executable, *arguments],
        capture_output=True,
        env=env,
        preexec_fn=lambda: os.close(1),
        timeout=10,
    )
    assert result.returncode == status, result.stderr
    assert result.stdout == b""
    if status:
        assert result.stderr == b""


@pytest.mark.parametrize("command", ["list", "ps"])
def test_empty_quiet_output_with_stdout_absent(command, monkeypatch):
    from chroot_distro import message
    from chroot_distro.commands import list_cmd, ps

    monkeypatch.setattr(message, "_quiet", False)
    monkeypatch.setattr("chroot_distro.cli._ensure_root_user", lambda: None)
    monkeypatch.setattr(list_cmd, "_iter_container_names", lambda: ([], []))
    monkeypatch.setattr(ps, "active_sessions", list)
    monkeypatch.setattr(ps, "containers_with_active_pids", dict)
    with patch("sys.stdout", None), patch("sys.argv", ["chroot-distro", command, "--quiet"]):
        main()


@pytest.mark.parametrize(
    ("error_type", "prefix"),
    [
        (ChrootDistroError, ""),
        (NotImplementedError, ""),
        (BrokenPipeError, "unexpected error: "),
    ],
)
def test_dispatch_escapes_stderr_without_changing_json(error_type, prefix, capsys):
    text = "peer\x1b[2J\x9b\u202e\nclosed"
    handler = MagicMock(side_effect=error_type(text))
    with (
        patch("sys.argv", ["chroot-distro", "diff", "demo", "--json"]),
        patch("chroot_distro.cli._ensure_root_user"),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"diff": handler}),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    out, err = capsys.readouterr()
    assert json.loads(out) == {"command": "diff", "error": prefix + text, "schema": 1}
    assert prefix + r"peer\e[2J\x9b\u202e\nclosed" in err
    assert not any(char in err for char in ("\x1b", "\x9b", "\u202e"))


def test_main_json_error_writes_a_document(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "diff", "ghost", "--json"]),
        patch("os.geteuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"diff": _finish}),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    _assert_json_error(capsys, "diff", "container 'ghost' is not installed.")


@pytest.mark.parametrize(
    ("arguments", "error"),
    [
        (["diff", "--json"], "container name is not specified."),
        (["diff", "box", "--json", "--bad\x1b[2J"], r"unrecognized option: '--bad\x1b[2J'."),
    ],
)
def test_main_json_validation_error(arguments, error, capsys):
    with (
        patch("sys.argv", ["chroot-distro", *arguments]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    ensure_root.assert_not_called()
    _assert_json_error(capsys, "diff", error)


@pytest.mark.parametrize(
    ("arguments", "command", "error"),
    [
        (["ps", "--json", "--quiet"], "ps", "argument -q/--quiet: not allowed with argument --json"),
        (["ls", "-q", "--j"], "list", "argument --json: not allowed with argument -q/--quiet"),
        (["nf", r"--json=a\b"], "info", r"argument --json: ignored explicit argument 'a\\b'"),
    ],
)
def test_main_json_parse_error(arguments, command, error, capsys):
    with (
        patch("sys.argv", ["chroot-distro", *arguments]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    ensure_root.assert_not_called()
    _assert_json_error(capsys, command, error)


def test_main_json_flag_after_separator_is_not_an_option(capsys):
    with patch("sys.argv", ["chroot-distro", "list", "--quiet=yes", "--", "--json"]), pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ignored explicit argument 'yes'" in captured.err


def test_main_json_elevation_error(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "nf", "--json"]),
        patch("chroot_distro.cli._ensure_root_user", side_effect=RootRequiredError("no root here")),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    _assert_json_error(capsys, "info", "no root here")


def test_main_json_handler_import_error(capsys):
    missing_module = "chroot_distro.commands._missing_for_test"
    with (
        patch("sys.argv", ["chroot-distro", "ls", "--json"]),
        patch("os.geteuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": f"{missing_module}:command_list"}),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    _assert_json_error(capsys, "list", f"unexpected error: No module named '{missing_module}'")


@pytest.mark.parametrize(
    ("arguments", "command"),
    [
        (["diff", "--json", "--help"], "diff"),
        (["ls", "--json", "--verbose", "--help"], "list"),
        (["ps", "--json", "--quiet", "-h"], "ps"),
        (["find", "--limit", "--help"], "search"),
        (["nf", "--usage"], "info"),
        (["--", "sh", "box", "--user", "--help"], "login"),
    ],
)
def test_main_help_precedes_validation(arguments, command, capsys):
    with (
        patch("sys.argv", ["chroot-distro", *arguments]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 0
    ensure_root.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"chroot-distro {command}" in captured.err


@pytest.mark.parametrize("prefix", [[], ["--"]])
def test_main_keeps_help_tokens_in_option_values_and_guest_arguments(prefix, capsys):
    handler = MagicMock()
    with (
        patch("sys.argv", ["chroot-distro", *prefix, "run", "box", "--entrypoint=--help", "--", "--help"]),
        patch("chroot_distro.cli._ensure_root_user"),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"run": handler}),
    ):
        main()

    handler.assert_called_once()
    args = handler.call_args.args[0]
    assert args.entrypoint == "--help"
    assert args.run_args == ["--help"]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("suffix", [["--help"], ["--version"], ["--", "help"]])
def test_main_rejects_options_after_leading_global_separator(suffix, capsys):
    with (
        patch("sys.argv", ["chroot-distro", "--", *suffix]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    ensure_root.assert_not_called()
    assert capsys.readouterr().out == ""


def test_main_without_json_writes_no_document(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "diff", "ghost"]),
        patch("os.geteuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"diff": _finish}),
        pytest.raises(SystemExit),
    ):
        main()
    assert capsys.readouterr().out == ""
