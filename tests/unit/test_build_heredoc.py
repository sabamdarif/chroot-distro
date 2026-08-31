# What a here-doc becomes. A here-doc is the shell's own syntax, so the three
# forms BuildKit tells apart have to be told apart here too: a lone `RUN <<EOF`
# runs its body, one whose body opens with a shebang is a script for the
# interpreter it names, and anything else is the shell's line to read.

import os
from types import SimpleNamespace

import pytest

from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.run_step import (
    _remove_step_script,
    _step_command,
    _write_step_script,
)
from chroot_distro.helpers.dockerfile import parse_dockerfile

SHELL = ["/bin/sh", "-c"]


def _run(text):
    """The single RUN record `text` parses to."""
    _, instructions = parse_dockerfile(text)
    return instructions[0]


def _stage(tmp_path=None):
    return SimpleNamespace(shell=list(SHELL), rootfs_dir=str(tmp_path or ""), rootfs_fd=None)


# ── which form a RUN takes ────────────────────────────────────────────────────
def test_a_plain_command_is_wrapped_in_the_shell():
    command, script = _step_command(_stage(), _run("RUN echo hi\n"))
    assert command == [*SHELL, "echo hi"]
    assert script is None


def test_an_exec_form_command_is_passed_through():
    command, script = _step_command(_stage(), _run('RUN ["echo", "hi"]\n'))
    assert command == ["echo", "hi"]
    assert script is None


def test_a_lone_heredoc_runs_its_body():
    command, script = _step_command(_stage(), _run("RUN <<EOF\necho one\necho two\nEOF\n"))
    assert command == [*SHELL, "echo one\necho two\n"]
    assert script is None


def test_a_dash_heredoc_runs_its_body_without_the_tabs():
    command, _ = _step_command(_stage(), _run("RUN <<-EOF\n\techo one\n\tEOF\n"))
    assert command == [*SHELL, "echo one\n"]


def test_a_redirect_reaches_the_shell_with_its_body():
    # Reading only the body ran `cat > /f` as nothing at all and lost the file.
    command, script = _step_command(_stage(), _run("RUN cat <<EOF > /f\nline\nEOF\n"))
    assert command == [*SHELL, "cat <<EOF > /f\nline\nEOF"]
    assert script is None


def test_a_command_before_the_heredoc_reaches_the_shell():
    command, _ = _step_command(_stage(), _run("RUN python3 <<EOF\nprint(1)\nEOF\n"))
    assert command == [*SHELL, "python3 <<EOF\nprint(1)\nEOF"]


def test_two_heredocs_reach_the_shell_in_order():
    command, script = _step_command(_stage(), _run("RUN cat <<A <<B\none\nA\ntwo\nB\n"))
    assert command == [*SHELL, "cat <<A <<B\none\nA\ntwo\nB"]
    assert script is None


def test_a_shebang_body_becomes_a_script_to_exec():
    command, script = _step_command(_stage(), _run("RUN <<EOF\n#!/usr/bin/env python3\nprint(1)\nEOF\n"))
    assert script is not None
    name, body = script
    assert command == ["/" + name]
    assert body == "#!/usr/bin/env python3\nprint(1)\n"


def test_two_shebang_scripts_do_not_share_a_name():
    _, first = _step_command(_stage(), _run("RUN <<EOF\n#!/bin/sh\ntrue\nEOF\n"))
    _, second = _step_command(_stage(), _run("RUN <<EOF\n#!/bin/sh\ntrue\nEOF\n"))
    assert first is not None and second is not None
    assert first[0] != second[0]


# ── planting the script, and taking it back out ───────────────────────────────
def test_the_script_is_written_executable_and_removed_again(tmp_path):
    stage = _stage(tmp_path)

    _write_step_script(stage, ".script", "#!/bin/sh\ntrue\n")

    written = tmp_path / ".script"
    assert written.read_text() == "#!/bin/sh\ntrue\n"
    assert os.stat(written).st_mode & 0o777 == 0o755

    _remove_step_script(stage, ".script")
    assert not written.exists()


def test_a_rootfs_that_cannot_hold_the_script_is_a_build_error(tmp_path):
    with pytest.raises(BuildError, match="here-doc script"):
        _write_step_script(_stage(tmp_path / "gone"), ".script", "#!/bin/sh\n")
