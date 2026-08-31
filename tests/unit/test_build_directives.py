# What a Dockerfile's parser directives mean to a build. `escape` is the parser's
# own business and `check` only turns off build checks this program never makes,
# but `syntax` names the program a Dockerfile wants to be built by: BuildKit
# fetches that image and hands the file over, and this program cannot, so what it
# builds is its own reading of the file. Silence there would be a build the
# Dockerfile did not ask for.

from chroot_distro.commands import build as build_cmd


def _warn(syntax):
    return build_cmd._warn_foreign_frontend({"syntax": syntax} if syntax else {})


def test_no_directive_says_nothing(capsys):
    _warn("")
    assert capsys.readouterr().err == ""


def test_the_stock_frontend_says_nothing(capsys):
    for ref in (
        "docker/dockerfile:1",
        "docker/dockerfile:1.7-labs",
        "docker/dockerfile",
        "docker.io/docker/dockerfile:1",
        "docker/dockerfile@sha256:" + "0" * 64,
    ):
        _warn(ref)
    assert capsys.readouterr().err == ""


def test_another_frontend_is_named(capsys):
    _warn("example.com/team/frontend:2")

    err = capsys.readouterr().err
    assert "example.com/team/frontend:2" in err
    assert "ordinary Dockerfile" in err
