import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chroot_distro.helpers.build_engine.engine import BuildEngine
from chroot_distro.helpers.build_engine.events import (
    BuildEvent,
    JSONReporter,
    NullReporter,
    PlainReporter,
    PlatformReporter,
    TTYReporter,
    make_reporter,
)
from chroot_distro.message import C, StdoutError


class _Recorder:
    def __init__(self):
        self.events = []

    def emit(self, ev):
        self.events.append(ev)


# ── event emission through the engine ─────────────────────────────────────────
def _engine(tmp_path, reporter):
    return BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path / "tmp"),
        target_arch_pd="aarch64",
        user_build_args={},
        target_stage=None,
        verbose=False,
        quiet=False,
        no_cache=False,
        emulator=None,
        reporter=reporter,
    )


def test_step_started_then_finished_per_step(tmp_path):
    from chroot_distro.helpers.dockerfile import parse_dockerfile

    rec = _Recorder()
    engine = _engine(tmp_path, rec)
    _, instructions = parse_dockerfile("FROM scratch\nENV A=1\n")
    engine.run(instructions)

    kinds = [ev.kind for ev in rec.events]
    assert kinds == ["step_started", "step_finished", "step_started", "step_finished"]
    finished = [ev for ev in rec.events if ev.kind == "step_finished"]
    assert all(ev.duration is not None for ev in finished)
    env_started = rec.events[2]
    assert env_started.instruction == "ENV"
    assert env_started.step_no == 2
    assert env_started.step_total == 2
    assert env_started.text == "ENV A=1"


def test_run_cache_hit_emits_event(tmp_path):
    from chroot_distro.arch import Platform
    from chroot_distro.helpers.build_engine import run_step

    layer = tmp_path / "layer.tar.gz"
    layer.write_bytes(b"")
    stage = SimpleNamespace(
        rootfs_dir=str(tmp_path),
        rootfs_fd=None,
        layers=[],
        parent_layer_digest=None,
        shell=["/bin/sh", "-c"],
        platform=Platform("linux", "arm64"),
        base_manifest_digest="sha256:m",
    )
    hits = []
    engine = SimpleNamespace(
        current=stage,
        no_cache=False,
        expansion_scope=dict,
        report_cache_hit=lambda instr: hits.append(instr["name"]),
        target_platform=Platform("linux", "arm64"),
        build_platform=Platform("linux", "amd64"),
        isolation_mode="none",
        stages={},
        step_recipes=set(),
    )
    hit = {"layer_digest": "sha256:x", "size": 1, "diff_id": "sha256:y"}
    instr = {"name": "RUN", "flags": {}, "value": "echo", "exec_form": False, "heredocs": [], "lineno": 1}
    with (
        patch.object(run_step, "cache_lookup", return_value=hit),
        patch.object(run_step, "layer_cache_path", return_value=str(layer)),
        patch.object(run_step, "apply_layer") as apply,
    ):
        run_step.do_run(engine, instr)
    assert hits == ["RUN"]
    apply.assert_called_once()
    assert stage.layers == [{"digest": "sha256:x", "size": 1, "diff_id": "sha256:y"}]


# ── PlainReporter ─────────────────────────────────────────────────────────────
def _ev(kind, **kw):
    return BuildEvent(kind=kind, **kw)


def test_plain_step_started_snapshot(capsys):
    PlainReporter().emit(_ev("step_started", step_no=3, step_total=9, stage_name="builder", text="RUN echo hi"))
    assert capsys.readouterr().err == "[*] Step 3/9 [builder]: RUN echo hi\n"


def test_plain_cached_marker(capsys):
    PlainReporter().emit(_ev("cache_hit", step_no=1, step_total=1))
    assert "CACHED" in capsys.readouterr().err


def test_plain_duration_on_finish(capsys):
    PlainReporter().emit(_ev("step_finished", duration=1.23))
    assert "done (1.2s)" in capsys.readouterr().err


def test_plain_fast_finish_is_silent(capsys):
    PlainReporter().emit(_ev("step_finished", duration=0.01))
    assert capsys.readouterr().err == ""


def test_plain_log_line(capsys):
    PlainReporter().emit(_ev("log_line", text="Packing layer..."))
    assert "Packing layer..." in capsys.readouterr().err


# ── TTYReporter ───────────────────────────────────────────────────────────────
def test_tty_inflight_then_collapse():
    out = io.StringIO()
    rep = TTYReporter(stream=out)
    rep.emit(_ev("step_started", step_no=1, step_total=2, stage_name="b", instruction="RUN", text="RUN make"))
    rep.emit(_ev("step_finished", step_no=1, step_total=2, duration=1.5))
    text = out.getvalue()
    assert "#1 [b] RUN" in text
    assert "done 1.5s" in text
    assert text.endswith("\n")


def test_tty_cached_collapse_swallows_finish():
    out = io.StringIO()
    rep = TTYReporter(stream=out)
    rep.emit(_ev("step_started", step_no=1, step_total=1, instruction="RUN", text="RUN make"))
    rep.emit(_ev("cache_hit", step_no=1, step_total=1))
    rep.emit(_ev("step_finished", step_no=1, step_total=1, duration=0.2))
    text = out.getvalue()
    assert "CACHED" in text
    assert "done" not in text


@pytest.mark.parametrize(("reporter", "limit"), [(PlainReporter, 120), (TTYReporter, 80)])
def test_build_reporters_escape_human_events(reporter, limit, monkeypatch, capsys):
    bad = "bad\x1b[2J\x9b\u202e\nnext"
    escaped = r"bad\e[2J\x9b\u202e\nnext"
    text = f"RUN\t{bad} " + "x" * 200
    step = _ev("step_started", platform=bad, stage_name=bad, instruction=bad, text=text)
    monkeypatch.setitem(C, "YELLOW", "\x1b[33m")
    monkeypatch.setitem(C, "CYAN", "\x1b[36m")
    monkeypatch.setitem(C, "RST", "\x1b[0m")

    renderer = reporter()
    renderer.emit(step)
    out, err = capsys.readouterr()
    assert not out
    assert f"[{escaped} {escaped}]" in err
    assert all(control not in err for control in ("\x1b[2J", "\x9b", "\u202e", "\nnext"))
    if reporter is PlainReporter:
        assert "\x1b[33mRUN\x1b[0m " in err
        preview = "RUN " + err.split("\x1b[33mRUN\x1b[0m ", 1)[1].removesuffix("\x1b[0m\n")
    else:
        assert err.startswith("\r\x1b[K\x1b[36m")
        assert f"] {escaped}\x1b[0m " in err
        preview = err.split("\x1b[0m ", 1)[1]
    assert len(preview) == limit
    assert escaped in preview
    assert preview.endswith("...")

    for kind in ("log_line", "error"):
        renderer.emit(_ev(kind, text=bad))
        out, err = capsys.readouterr()
        assert not out
        assert escaped in err
        assert all(control not in err for control in ("\x1b[2J", "\x9b", "\u202e", "\nnext"))

    JSONReporter().emit(step)
    out, err = capsys.readouterr()
    assert not err
    event = json.loads(out)
    assert event["text"] == text
    assert event["stage_name"] == event["platform"] == event["instruction"] == bad


# ── JSONReporter ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("method", ["write", "flush"])
def test_json_reporter_preserves_explicit_stream_error(monkeypatch, method):
    from unittest.mock import Mock

    error = BrokenPipeError("closed")
    stream = Mock()
    getattr(stream, method).side_effect = error
    monkeypatch.setattr(sys, "stdout", stream)
    with pytest.raises(StdoutError) as exc:
        JSONReporter().emit(_ev("step_started"))
    assert exc.value.stream is stream
    with pytest.raises(BrokenPipeError) as exc:
        JSONReporter(stream=stream).emit(_ev("step_started"))
    assert exc.value is error


@pytest.mark.skipif(sys.platform != "linux", reason="Build uses Linux filesystem calls")
@pytest.mark.parametrize("stdout_mode", ["open", "buffered-pipe", "unbuffered-pipe", "absent"])
def test_raw_json_build_stdout(tmp_path, stdout_mode):
    (tmp_path / "Dockerfile").write_text("FROM scratch\nENV A=1\n")
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
        "XDG_DATA_HOME": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path),
    }
    command = [sys.executable]
    if stdout_mode == "unbuffered-pipe":
        command.append("-u")
    command += [
        "-c",
        "from chroot_distro import cli; cli._ensure_root_user = lambda: None; cli.main()",
        "build", "--progress=rawjson", "-t", "stdout-test", str(tmp_path),
    ]
    options = {"stdout": subprocess.PIPE}
    if stdout_mode == "absent":
        options["preexec_fn"] = lambda: os.close(1)
    elif stdout_mode.endswith("-pipe"):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        options["stdout"] = write_fd
    try:
        result = subprocess.run(command, stderr=subprocess.PIPE, env=env, timeout=10, **options)
    finally:
        if stdout_mode.endswith("-pipe"):
            os.close(write_fd)

    store = tmp_path / "chroot-distro"
    assert not list((store / "build-tmp").iterdir())
    manifests = store / "oci_manifests"
    if stdout_mode == "open":
        assert result.returncode == 0, result.stderr
        assert [json.loads(line)["kind"] for line in result.stdout.splitlines()] == [
            "step_started", "step_finished", "step_started", "step_finished",
        ]
        assert list(manifests.rglob("*.json"))
    else:
        assert result.returncode == 1, result.stderr
        assert b"Broken pipe" not in result.stderr
        assert b"unexpected error" not in result.stderr
        assert b"Traceback" not in result.stderr
        assert not list(manifests.rglob("*.json"))


def test_json_reporter_emits_json_lines():
    out = io.StringIO()
    rep = JSONReporter(stream=out)
    rep.emit(_ev("step_started", step_no=1, step_total=2, instruction="RUN", text="RUN x", lineno=4))
    rep.emit(_ev("step_finished", step_no=1, step_total=2, duration=0.5))
    lines = out.getvalue().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first == {
        "kind": "step_started",
        "step_no": 1,
        "step_total": 2,
        "platform": "",
        "stage_name": "",
        "instruction": "RUN",
        "text": "RUN x",
        "duration": None,
        "lineno": 4,
    }
    assert json.loads(lines[1])["duration"] == 0.5


# ── PlatformReporter ──────────────────────────────────────────────────────────
def test_platform_is_named_before_the_stage(capsys):
    rep = PlatformReporter(PlainReporter(), "linux/arm64")

    rep.emit(_ev("step_started", step_no=1, step_total=2, stage_name="builder", text="RUN echo hi"))

    assert capsys.readouterr().err == "[*] Step 1/2 [linux/arm64 builder]: RUN echo hi\n"


def test_platform_alone_still_gets_brackets():
    out = io.StringIO()
    rep = PlatformReporter(TTYReporter(stream=out), "linux/arm/v7")

    rep.emit(_ev("step_started", step_no=1, step_total=1, instruction="RUN", text="RUN make"))

    assert "#1 [linux/arm/v7] RUN" in out.getvalue()


def test_the_engine_keeps_its_own_event():
    rec = _Recorder()
    ev = _ev("step_started", step_no=1)

    PlatformReporter(rec, "linux/amd64").emit(ev)

    assert ev.platform == ""
    assert rec.events[0].platform == "linux/amd64"


# ── make_reporter ─────────────────────────────────────────────────────────────
def test_quiet_wins():
    assert isinstance(make_reporter("rawjson", quiet=True), NullReporter)


def test_a_named_platform_wraps_the_renderer():
    assert isinstance(make_reporter("plain", quiet=False, platform="linux/amd64"), PlatformReporter)


def test_quiet_wins_over_a_named_platform():
    assert isinstance(make_reporter("plain", quiet=True, platform="linux/amd64"), NullReporter)


@pytest.mark.parametrize(
    ("progress", "cls"),
    [("plain", PlainReporter), ("tty", TTYReporter), ("rawjson", JSONReporter)],
)
def test_explicit_progress_choices(progress, cls):
    assert isinstance(make_reporter(progress, quiet=False), cls)


def test_auto_is_plain_when_stderr_not_tty():
    with patch("sys.stderr") as err:
        err.isatty.return_value = False
        assert isinstance(make_reporter("auto", quiet=False), PlainReporter)


def test_auto_is_tty_on_terminal():
    with patch("sys.stderr") as err:
        err.isatty.return_value = True
        assert isinstance(make_reporter("auto", quiet=False), TTYReporter)


def test_engine_quiet_defaults_to_null_reporter(tmp_path):
    engine = BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path / "tmp"),
        target_arch_pd="aarch64",
        user_build_args={},
        target_stage=None,
        verbose=False,
        quiet=True,
        no_cache=False,
        emulator=None,
    )
    assert isinstance(engine.reporter, NullReporter)
