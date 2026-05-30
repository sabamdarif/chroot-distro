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
    assert args.image_ref == "ubuntu:20.04"
    assert args.custom_container_name == "myubuntu"


def test_parser_login():
    parser = build_parser()
    # Test typical login options
    args, unknown = parser.parse_known_args(["login", "alpine", "--shared-home", "--user", "user1", "--", "whoami"])
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


