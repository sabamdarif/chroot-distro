# What a failed build prints about the entry it failed on.
#
# A BuildError builds its message by interpolation, and the names it reports on
# belong to whoever wrote the image: a member of an ADD'd archive, a path out of
# a base image, the output of a RUN step's own tooling. So a member called
# $'\e[2J\e[31mPWNED' cleared the terminal of the user who built the Dockerfile
# that copied it.

import os
from types import SimpleNamespace

import pytest

from chroot_distro.commands import build as build_cmd
from chroot_distro.helpers.build_engine import BuildError

NASTY = "\x1b[2J\x1b[31mPWNED"


@pytest.fixture
def failing_build(monkeypatch, tmp_path):
    """A build that gets as far as the engine and then fails on *NASTY*."""
    ctx = tmp_path / "ctx"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM alpine\n")

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    class _Lock:
        lock_path = str(tmp_path / "lock")

        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    class _Engine:
        def __init__(self, *_a, **_k):
            pass

        def close(self):
            pass

        def run(self, _instructions):
            raise BuildError(f"Failed to write '{NASTY}' into rootfs: No such file or directory")

    monkeypatch.setattr(build_cmd, "BuildLock", _Lock)
    monkeypatch.setattr(build_cmd, "BuildEngine", _Engine)
    monkeypatch.setattr(
        build_cmd,
        "_make_build_tmp",
        lambda: (str(scratch), os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY), -1),
    )
    monkeypatch.setattr(build_cmd, "_remove_build_tmp", lambda _root, dir_fd: os.close(dir_fd))
    return ctx


def test_a_failure_escapes_the_name_it_reports(failing_build, capsys):
    with pytest.raises(SystemExit):
        build_cmd.command_build(SimpleNamespace(path=str(failing_build)))

    err = capsys.readouterr().err
    assert "\x1b[2J" not in err
    assert "\\e[2J\\e[31mPWNED" in err
