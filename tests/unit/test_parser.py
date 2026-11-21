import pytest

from chroot_distro.parser import ALIAS_TO_CANONICAL, build_parser


def test_parser_basic():
    parser = build_parser()

    # Test 'list' command
    args = parser.parse_args(["list"])
    assert args.command == "list"
    assert args.quiet is False

    # Test alias mapping in tests
    assert ALIAS_TO_CANONICAL["ls"] == "list"
    assert ALIAS_TO_CANONICAL["sh"] == "login"
    assert ALIAS_TO_CANONICAL["add"] == "install"


def test_parser_install():
    parser = build_parser()
    args = parser.parse_args(["install", "ubuntu:20.04", "--name", "myubuntu"])
    assert args.command == "install"
    assert args.image_ref == ["ubuntu:20.04"]
    assert args.custom_container_name == "myubuntu"


def test_parser_login():
    parser = build_parser()
    # Test typical login options
    args, unknown = parser.parse_known_args(["login", "alpine", "--shared-home", "--user", "user1", "--", "whoami"])
    assert args.command == "login"
    assert args.container_name == "alpine"
    assert args.shared_home is True
    assert args.user == "user1"
    assert args.login_cmd == ["whoami"]
    assert unknown == []


def test_parser_login_isolated():
    parser = build_parser()
    args = parser.parse_args(["login", "alpine", "--isolated"])
    assert args.isolated is True
    assert args.minimal is False


def test_parser_login_isolated_minimal_exclusive():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["login", "alpine", "--isolated", "--minimal"])


def test_parser_login_isolate_alias():
    parser = build_parser()
    args = parser.parse_args(["login", "alpine", "--isolate"])
    assert args.isolated is True
    assert args.minimal is False


def test_parser_run_isolate_alias():
    parser = build_parser()
    args = parser.parse_args(["run", "alpine", "--isolate"])
    assert args.isolated is True


def test_parser_run_captures_run_args():
    parser = build_parser()
    args, unknown = parser.parse_known_args(["run", "cloudflared", "--", "--help"])
    assert args.command == "run"
    assert args.container_name == "cloudflared"
    assert args.run_args == ["--help"]
    assert unknown == []


def test_parser_run_captures_multiple_run_args():
    parser = build_parser()
    args, _ = parser.parse_known_args(["run", "alpine", "--isolate", "--", "tunnel", "run"])
    assert args.isolated is True
    assert args.run_args == ["tunnel", "run"]


def test_parser_run_detach_default_false():
    parser = build_parser()
    args = parser.parse_args(["run", "alpine"])
    assert args.detach is False


def test_parser_run_detach_long_flag():
    parser = build_parser()
    args = parser.parse_args(["run", "alpine", "--detach"])
    assert args.detach is True


def test_parser_run_detach_short_flag():
    parser = build_parser()
    args = parser.parse_args(["run", "-d", "alpine"])
    assert args.detach is True


def test_parser_run_detach_with_run_args():
    parser = build_parser()
    args, _ = parser.parse_known_args(["run", "alpine", "--detach", "--", "sleep", "100"])
    assert args.detach is True
    assert args.run_args == ["sleep", "100"]


def test_parser_run_entrypoint():
    parser = build_parser()
    args, _ = parser.parse_known_args(["run", "alpine", "--entrypoint", "/bin/echo", "--", "hi"])
    assert args.command == "run"
    assert args.entrypoint == "/bin/echo"
    assert args.run_args == ["hi"]


def test_parser_run_entrypoint_defaults_none():
    parser = build_parser()
    args = parser.parse_args(["run", "alpine"])
    assert args.entrypoint is None


def test_parser_login_has_no_entrypoint():
    # --entrypoint is a run-only flag; login must not define it.
    parser = build_parser()
    args, unknown = parser.parse_known_args(["login", "alpine", "--entrypoint", "/bin/echo"])
    assert not hasattr(args, "entrypoint")
    assert "--entrypoint" in unknown


@pytest.mark.parametrize(("command", "dest"), [("sh", "login_cmd"), ("run", "run_args")])
@pytest.mark.parametrize("guest_args", [[], ["--help", "--", ""]])
def test_guest_arguments_are_kept_verbatim(command, dest, guest_args):
    args, unknown = build_parser().parse_known_args([command, "box", "--unknown", "--", *guest_args])
    assert args.container_name == "box"
    assert args.help is False
    assert getattr(args, dest) == guest_args
    assert unknown == ["--unknown"]


@pytest.mark.parametrize(
    ("words", "expected"),
    [
        (["echo", "hello"], ["echo", "hello"]),
        (["echo", "--", "hello"], ["echo", "hello"]),
        (["echo", "--"], ["echo"]),
        (["echo", "--", "--", ""], ["echo", "--", ""]),
    ],
)
def test_login_keeps_bare_guest_command(words, expected):
    args = build_parser().parse_args(["login", "box", *words])
    assert args.login_cmd == expected


def test_leading_global_separator_preserves_the_guest_separator():
    args = build_parser().parse_args(["--", "sh", "box", "echo", "--", "--help"])
    assert args.command == "sh"
    assert args.container_name == "box"
    assert args.help is False
    assert args.login_cmd == ["echo", "--help"]


def test_guest_argument_cannot_fill_a_host_option_value(capsys):
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["login", "box", "--user", "--", "alice"])

    assert exc_info.value.code == 1
    assert "expected one argument" in capsys.readouterr().err


@pytest.mark.parametrize("user_option", ["--user=--", "-u=--", "-u--"])
def test_parser_keeps_attached_literal_separator(user_option):
    args = build_parser().parse_args(["login", "box", user_option, "--env=--", "--", "echo"])
    assert args.user == "--"
    assert args.env == ["--"]
    assert args.login_cmd == ["echo"]


def test_parser_keeps_attached_literal_separator_as_optional_value():
    args = build_parser().parse_args(["build", "--ssh=--", "--ssh"])
    assert args.ssh == ["--", "default"]


@pytest.mark.parametrize(
    ("argv", "diagnostic"),
    [
        (["build", "--progress=--"], "invalid choice: '--'"),
        (["search", "--limit=--", "term"], "invalid int value: '--'"),
    ],
)
def test_parser_validates_attached_literal_separator(argv, diagnostic, capsys):
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(argv)
    assert exc_info.value.code == 1
    assert diagnostic in capsys.readouterr().err


def test_parser_build_secret_and_ssh():
    parser = build_parser()
    args = parser.parse_args(["build", ".", "--secret", "id=tok,src=/tmp/tok", "--secret", "id=other", "--ssh"])
    assert args.command == "build"
    assert args.secrets == ["id=tok,src=/tmp/tok", "id=other"]
    assert args.ssh == ["default"]


def test_parser_build_ssh_with_value():
    parser = build_parser()
    args = parser.parse_args(["build", ".", "--ssh", "deploy=/run/agent.sock"])
    assert args.ssh == ["deploy=/run/agent.sock"]


def test_parser_build_secret_ssh_default_empty():
    parser = build_parser()
    args = parser.parse_args(["build", "."])
    assert args.secrets == []
    assert args.ssh == []


def test_parser_build_platform_repeatable():
    parser = build_parser()
    args = parser.parse_args(["build", ".", "--platform", "linux/amd64,linux/arm64", "--platform", "linux/arm/v7"])
    assert args.platforms == ["linux/amd64,linux/arm64", "linux/arm/v7"]
    assert parser.parse_args(["build", "."]).platforms == []


def test_parser_build_progress():
    parser = build_parser()
    for value in ("auto", "plain", "tty", "rawjson"):
        args = parser.parse_args(["build", ".", "--progress", value])
        assert args.progress == value
    assert parser.parse_args(["build", "."]).progress == "auto"


def test_parser_build_progress_invalid_rejected():
    import pytest

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["build", ".", "--progress", "fancy"])


def test_parser_clear_cache_build_cache():
    parser = build_parser()
    assert parser.parse_args(["clear-cache"]).build_cache is False
    args = parser.parse_args(["clear-cache", "--build-cache", "--verbose"])
    assert args.build_cache is True
    assert args.verbose is True


@pytest.mark.parametrize("command", ["list", "ps", "info", "diff"])
def test_parser_json_flag(command):
    parser = build_parser()
    argv = [command, "--json"] if command != "diff" else [command, "demo", "--json"]
    assert parser.parse_args(argv).json is True

    plain = [command] if command != "diff" else [command, "demo"]
    assert parser.parse_args(plain).json is False


@pytest.mark.parametrize("command", ["list", "ps"])
def test_parser_json_and_quiet_are_exclusive(command):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([command, "--json", "-q"])
    with pytest.raises(SystemExit):
        parser.parse_args([command, "-q", "--json"])
