# What a failed build prints about the entry it failed on.
#
# A BuildError builds its message by interpolation, and the names it reports on
# belong to whoever wrote the image: a member of an ADD'd archive, a path out of
# a base image, the output of a RUN step's own tooling. So a member called
# $'\e[2J\e[31mPWNED' cleared the terminal of the user who built the Dockerfile
# that copied it.

import errno
import os
from types import SimpleNamespace

import pytest

from chroot_distro.commands import build as build_cmd
from chroot_distro.helpers.build_engine import BuildError
from chroot_distro.helpers.build_engine import solve as solve_mod

NASTY = "\x1b[2J\x1b[31mPWNED"


@pytest.fixture
def failing_build(monkeypatch, tmp_path):
    """Make a build that gets as far as the engine and then raises *exc*."""
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
            raise _Engine.failure

    monkeypatch.setattr(build_cmd, "BuildLock", _Lock)
    monkeypatch.setattr(solve_mod, "BuildEngine", _Engine)
    monkeypatch.setattr(
        build_cmd,
        "_make_build_tmp",
        lambda: (
            str(scratch),
            os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY),
            os.open(str(scratch), os.O_RDONLY | os.O_DIRECTORY),
        ),
    )
    monkeypatch.setattr(build_cmd, "_remove_build_tmp", lambda _root, dir_fd: os.close(dir_fd))

    def _run(exc):
        _Engine.failure = exc
        with pytest.raises(SystemExit):
            build_cmd.command_build(SimpleNamespace(path=str(ctx)))

    return _run


def test_a_failure_escapes_the_name_it_reports(failing_build, capsys):
    failing_build(BuildError(f"Failed to write '{NASTY}' into rootfs: No such file or directory"))

    err = capsys.readouterr().err
    assert "\x1b[2J" not in err
    assert "\\e[2J\\e[31mPWNED" in err


def test_a_walk_losing_its_footing_is_a_build_failure(failing_build, capsys):
    # dirfd.Levels reopens a parked level through its child's "..", and raises
    # ESTALE when what it finds is not the directory it recorded. That reaches
    # command_build as an OSError, which is still the build failing.
    failing_build(OSError(errno.ESTALE, "Stale file handle"))

    err = capsys.readouterr().err
    assert "Build failed: Stale file handle" in err
    assert "unexpected error" not in err
