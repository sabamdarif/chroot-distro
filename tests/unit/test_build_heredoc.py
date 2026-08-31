# What a here-doc becomes. A here-doc is the shell's own syntax, so the three
# forms BuildKit tells apart have to be told apart here too: a lone `RUN <<EOF`
# runs its body, one whose body opens with a shebang is a script for the
# interpreter it names, and anything else is the shell's line to read.

import os
from types import SimpleNamespace

import pytest

from chroot_distro.helpers.build_engine import copy_step
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
    assert first is not None
    assert second is not None
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


# ── COPY and ADD from an inline body ──────────────────────────────────────────
class _CopyStage:
    def __init__(self, base):
        self.rootfs_dir = str(base / "rootfs")
        self.rootfs_fd = None
        self.workdir = "/"
        self.layers = []
        self.parent_layer_digest = None
        self.index = 0
        os.makedirs(self.rootfs_dir, exist_ok=True)


class _CopyEngine:
    def __init__(self, base):
        self.build_dir = str(base / "ctx")
        self.tmp_root = str(base / "tmp")
        self.ignore_patterns = []
        self.stages = {}
        self.quiet = True
        self.current = _CopyStage(base)
        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(self.tmp_root, exist_ok=True)

    def expansion_scope(self):
        return {"FOO": "bar"}


@pytest.fixture
def copy_engine(tmp_path, monkeypatch):
    layer_dir = tmp_path / "layers"
    layer_dir.mkdir()
    monkeypatch.setattr(copy_step, "layer_cache_path", lambda digest: str(layer_dir / digest.replace(":", "_")))
    return _CopyEngine(tmp_path)


def _copy(engine, text):
    """Run the single COPY/ADD `text` parses to against *engine*."""
    instr = _run(text)
    handler = copy_step.do_add if instr["name"] == "ADD" else copy_step.do_copy
    handler(engine, instr)
    return engine.current.rootfs_dir


def test_a_heredoc_body_becomes_the_destination_file(copy_engine):
    rootfs = _copy(copy_engine, "COPY <<EOF /etc/conf\nkey = value\nEOF\n")
    written = os.path.join(rootfs, "etc/conf")
    with open(written) as fh:
        assert fh.read() == "key = value\n"
    assert os.stat(written).st_mode & 0o777 == 0o644


def test_a_heredoc_into_a_directory_is_named_after_its_tag(copy_engine):
    rootfs = _copy(copy_engine, "COPY <<motd /etc/\nhello\nmotd\n")
    assert os.path.isfile(os.path.join(rootfs, "etc/motd"))


def test_two_heredocs_land_side_by_side(copy_engine):
    rootfs = _copy(copy_engine, "COPY <<one <<two /etc/\nfirst\none\nsecond\ntwo\n")
    with open(os.path.join(rootfs, "etc/one")) as fh:
        assert fh.read() == "first\n"
    with open(os.path.join(rootfs, "etc/two")) as fh:
        assert fh.read() == "second\n"


def test_chmod_applies_to_a_heredoc(copy_engine):
    rootfs = _copy(copy_engine, "COPY --chmod=755 <<EOF /run.sh\n#!/bin/sh\nEOF\n")
    assert os.stat(os.path.join(rootfs, "run.sh")).st_mode & 0o777 == 0o755


def test_an_unquoted_tag_expands_the_body(copy_engine):
    rootfs = _copy(copy_engine, "COPY <<EOF /f\nvalue=$FOO\nEOF\n")
    with open(os.path.join(rootfs, "f")) as fh:
        assert fh.read() == "value=bar\n"


def test_a_quoted_tag_keeps_the_body_verbatim(copy_engine):
    rootfs = _copy(copy_engine, 'COPY <<"EOF" /f\nvalue=$FOO\nEOF\n')
    with open(os.path.join(rootfs, "f")) as fh:
        assert fh.read() == "value=$FOO\n"


def test_an_add_takes_a_heredoc_too(copy_engine):
    rootfs = _copy(copy_engine, "ADD <<EOF /f\nhi\nEOF\n")
    assert os.path.isfile(os.path.join(rootfs, "f"))


def test_a_heredoc_cannot_be_the_destination(copy_engine):
    with pytest.raises(BuildError, match="destination"):
        _copy(copy_engine, "COPY /src <<EOF\nnope\nEOF\n")


def test_the_same_body_packs_the_same_layer(tmp_path, monkeypatch):
    text = "COPY <<EOF /f\ncontent\nEOF\n"
    digests = []
    for name in ("a", "b"):
        base = tmp_path / name
        base.mkdir()
        layer_dir = base / "layers"
        layer_dir.mkdir()
        monkeypatch.setattr(
            copy_step, "layer_cache_path", lambda digest, at=layer_dir: str(at / digest.replace(":", "_"))
        )
        engine = _CopyEngine(base)
        _copy(engine, text)
        digests.append(engine.current.layers[0]["digest"])
    # The body is part of the Dockerfile, so the clock must not reach the layer.
    assert digests[0] == digests[1]
