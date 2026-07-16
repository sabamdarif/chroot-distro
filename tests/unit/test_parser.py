import pytest

from chroot_distro.parser import ALIAS_TO_CANONICAL, build_parser, parse_cli_args


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
    args, unknown = parse_cli_args(parser, ["login", "alpine", "--shared-home", "--user", "user1", "--", "whoami"])
    assert args.command == "login"
    assert args.container_name == "alpine"
    assert args.shared_home is True
    assert args.user == "user1"
    # positional arguments after the login command are consumed by login_cmd (without '--')
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
    args, unknown = parse_cli_args(parser, ["run", "cloudflared", "--", "--help"])
    assert args.command == "run"
    assert args.container_name == "cloudflared"
    assert args.run_args == ["--help"]
    assert unknown == ["--help"]


def test_parser_run_captures_multiple_run_args():
    parser = build_parser()
    args, _ = parse_cli_args(parser, ["run", "alpine", "--isolate", "--", "tunnel", "run"])
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
    args, _ = parse_cli_args(parser, ["run", "alpine", "--detach", "--", "sleep", "100"])
    assert args.detach is True
    assert args.run_args == ["sleep", "100"]


def test_parser_run_entrypoint():
    parser = build_parser()
    args, _ = parse_cli_args(parser, ["run", "alpine", "--entrypoint", "/bin/echo", "--", "hi"])
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
    args, unknown = parse_cli_args(parser, ["login", "alpine", "--entrypoint", "/bin/echo"])
    assert not hasattr(args, "entrypoint")
    assert "--entrypoint" in unknown
