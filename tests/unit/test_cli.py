import json
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.cli import _ensure_root_user, main
from chroot_distro.exceptions import RootRequiredError


def test_ensure_root_user():
    # As non-root, it should call elevate_or_die
    with patch("os.getuid", return_value=1000), patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
        _ensure_root_user()
        mock_elevate.assert_called_once()

    # As root, it should pass without raising and not call elevate_or_die
    with patch("os.getuid", return_value=0), patch("chroot_distro.elevate.elevate_or_die") as mock_elevate:
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
        patch("os.getuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": mock_list}),
    ):
        main()
        mock_list.assert_called_once()


def test_main_login_requires_root():
    # Running login as non-root (UID 1000) should attempt privilege elevation
    # Mock elevate_or_die to raise RootRequiredError to simulate failed/disabled elevation
    with (
        patch("sys.argv", ["chroot-distro", "login", "alpine"]),
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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
        patch("os.getuid", return_value=1000),
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


def test_main_json_error_writes_a_document(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "diff", "ghost", "--json"]),
        patch("os.getuid", return_value=0),
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
        patch("os.getuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"list": f"{missing_module}:command_list"}),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
    _assert_json_error(capsys, "list", f"unexpected error: No module named '{missing_module}'")


def test_main_json_help(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "diff", "--json", "--help"]),
        patch("chroot_distro.cli._ensure_root_user") as ensure_root,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 0
    ensure_root.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "chroot-distro diff" in captured.err


def test_main_without_json_writes_no_document(capsys):
    with (
        patch("sys.argv", ["chroot-distro", "diff", "ghost"]),
        patch("os.getuid", return_value=0),
        patch.dict("chroot_distro.cli._COMMAND_HANDLERS", {"diff": _finish}),
        pytest.raises(SystemExit),
    ):
        main()
    assert capsys.readouterr().out == ""
