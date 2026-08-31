import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chroot_distro.helpers.build_engine.engine import BuildEngine
from chroot_distro.helpers.build_engine.events import (
    BuildEvent,
    JSONReporter,
    NullReporter,
    PlainReporter,
    TTYReporter,
    make_reporter,
)


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


# ── JSONReporter ──────────────────────────────────────────────────────────────
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
        "stage_name": "",
        "instruction": "RUN",
        "text": "RUN x",
        "duration": None,
        "lineno": 4,
    }
    assert json.loads(lines[1])["duration"] == 0.5


# ── make_reporter ─────────────────────────────────────────────────────────────
def test_quiet_wins():
    assert isinstance(make_reporter("rawjson", quiet=True), NullReporter)


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
