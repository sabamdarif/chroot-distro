# An ONBUILD trigger fires for whoever builds FROM the image or stage that
# recorded it, exactly once, and is not carried on by the image that fired it.
# History is what counts the firings here: every fired trigger appends one
# entry, and a stage inherits its parent's array, so a trigger that fired twice
# shows up twice.

import pytest

from chroot_distro.arch import Platform
from chroot_distro.helpers.build_engine import engine as engine_mod
from chroot_distro.helpers.build_engine.engine import BuildEngine
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.dockerfile import parse_dockerfile

TARGET = Platform("linux", "amd64")


def _engine(tmp_path, **kwargs):
    return BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path / "tmp"),
        target_arch_pd="x86_64",
        user_build_args={},
        target_stage=None,
        verbose=False,
        quiet=True,
        no_cache=False,
        emulator=None,
        target_platform=TARGET,
        build_platform=TARGET,
        **kwargs,
    )


def _with_base(monkeypatch, tmp_path, text, on_build):
    """Run *text* with a base image whose config carries *on_build*."""
    monkeypatch.setattr(engine_mod, "log_info", lambda *_a, **_k: None)
    monkeypatch.setattr(
        engine_mod,
        "pull_image",
        lambda *_a, **_k: {"image_config": {"config": {"OnBuild": list(on_build)}}, "manifest": {}},
    )
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile(text)
    engine.run(instructions)
    return engine


def _fired(stage, created_by):
    return [h for h in stage.image_config.get("history", []) if h.get("created_by") == created_by]


# ── a base image's triggers ───────────────────────────────────────────────────
def test_a_base_images_trigger_fires_and_is_not_republished(monkeypatch, tmp_path):
    engine = _with_base(monkeypatch, tmp_path, "FROM img:1\n", ["ENV FOO=1"])

    cfg = engine.current.image_config["config"]
    assert cfg["Env"] == ["FOO=1"]
    assert engine.current.env["FOO"] == "1"
    # The trigger belongs to img:1, so the image this build publishes does not
    # announce it to whoever builds FROM *this* result.
    assert "OnBuild" not in cfg
    assert len(_fired(engine.current, "ENV FOO=1")) == 1


def test_a_trigger_does_not_fire_again_in_a_stage_built_from_the_result(monkeypatch, tmp_path):
    engine = _with_base(monkeypatch, tmp_path, "FROM img:1 AS one\nFROM one AS two\n", ["ENV FOO=1"])

    assert len(_fired(engine.stages["two"], "ENV FOO=1")) == 1
    assert "OnBuild" not in engine.stages["two"].image_config["config"]


def test_a_trigger_that_does_not_parse_names_the_base(monkeypatch, tmp_path):
    with pytest.raises(BuildError, match="FROM img:1: ONBUILD trigger"):
        _with_base(monkeypatch, tmp_path, "FROM img:1\n", ["RUN <<EOF"])


def test_a_trigger_this_program_cannot_run_names_the_base(monkeypatch, tmp_path):
    with pytest.raises(BuildError, match="unsupported instruction 'ONBUILD'"):
        _with_base(monkeypatch, tmp_path, "FROM img:1\n", ["ONBUILD RUN echo hi"])


# ── a stage's own triggers ────────────────────────────────────────────────────
def test_a_stage_fires_the_triggers_its_parent_stage_recorded(tmp_path):
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile(
        "FROM scratch AS base\nONBUILD LABEL fired=yes\nFROM base AS child\nFROM child AS grand\n"
    )

    engine.run(instructions)

    base, child, grand = (engine.stages[name] for name in ("base", "child", "grand"))
    # The stage that recorded it publishes it and does not run it itself.
    assert base.image_config["config"]["OnBuild"] == ["LABEL fired=yes"]
    assert "Labels" not in base.image_config["config"]
    # The stage built FROM it runs it once, and stops carrying it.
    assert child.image_config["config"]["Labels"] == {"fired": "yes"}
    assert "OnBuild" not in child.image_config["config"]
    assert len(_fired(child, "LABEL fired=yes")) == 1
    # And the one after that inherits the label without firing anything again.
    assert grand.image_config["config"]["Labels"] == {"fired": "yes"}
    assert len(_fired(grand, "LABEL fired=yes")) == 1
