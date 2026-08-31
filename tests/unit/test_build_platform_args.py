import pytest

from chroot_distro.arch import Platform, parse_platform
from chroot_distro.helpers.build_engine import engine as engine_mod
from chroot_distro.helpers.build_engine.engine import BuildEngine, plan_stages
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.stage import Stage
from chroot_distro.helpers.dockerfile import parse_dockerfile

TARGET = Platform("linux", "arm64")
BUILD = Platform("linux", "amd64")


def _plan(text, args=None):
    _, instructions = parse_dockerfile(text)
    return plan_stages(
        instructions,
        target_platform=TARGET,
        build_platform=BUILD,
        user_build_args=args or {},
    )


def _engine(tmp_path, **kwargs):
    kwargs.setdefault("target_platform", TARGET)
    kwargs.setdefault("build_platform", BUILD)
    kwargs.setdefault("user_build_args", {})
    return BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path / "tmp"),
        target_arch_pd="x86_64",
        target_stage=None,
        verbose=False,
        quiet=True,
        no_cache=False,
        emulator=None,
        **kwargs,
    )


# ── the automatic platform values ─────────────────────────────────────────────
def test_engine_platform_args_include_variants(tmp_path):
    engine = _engine(tmp_path, target_platform=Platform("linux", "arm", "v7"))

    assert engine.platform_args() == {
        "TARGETPLATFORM": "linux/arm/v7",
        "TARGETOS": "linux",
        "TARGETARCH": "arm",
        "TARGETVARIANT": "v7",
        "BUILDPLATFORM": "linux/amd64",
        "BUILDOS": "linux",
        "BUILDARCH": "amd64",
        "BUILDVARIANT": "",
    }


def test_stage_keeps_normalized_platform_and_legacy_arch(tmp_path):
    stage = Stage(
        index=0,
        name="builder",
        rootfs_dir=str(tmp_path),
        target_arch_pd="x86_64",
        platform=Platform("linux", "arm", "v7"),
    )

    assert stage.platform == Platform("linux", "arm", "v7")
    assert stage.target_arch_pd == "arm"


# ── one plan per FROM ─────────────────────────────────────────────────────────
def test_bare_from_takes_the_target_platform():
    plans, _ = _plan("FROM alpine\n")
    assert [(p.platform, p.runs) for p in plans] == [(TARGET, False)]


def test_build_and_target_platform_expressions():
    plans, _ = _plan(
        "FROM --platform=$BUILDPLATFORM golang AS builder\n"
        "RUN go build\n"
        "FROM --platform=$TARGETPLATFORM alpine\n"
        "COPY --from=builder /app /app\n"
    )
    assert [p.platform for p in plans] == [BUILD, TARGET]
    assert [p.runs for p in plans] == [True, False]


def test_a_heredoc_run_counts_as_running():
    plans, _ = _plan("FROM alpine\nRUN <<EOF\necho hi\nEOF\n")
    assert plans[0].runs is True


def test_explicit_platform_comes_from_a_global_arg():
    plans, global_args = _plan('ARG PLAT=linux/arm/v7\nFROM --platform="$PLAT" alpine\n')
    assert plans[0].platform == Platform("linux", "arm", "v7")
    assert global_args == {"PLAT": "linux/arm/v7"}


def test_a_build_arg_overrides_the_platform_expression():
    plans, _ = _plan("ARG PLAT=linux/arm/v7\nFROM --platform=$PLAT alpine\n", args={"PLAT": "linux/386"})
    assert plans[0].platform == Platform("linux", "386")


def test_an_arg_after_the_first_from_is_not_global():
    _plans, global_args = _plan("ARG A=1\nFROM alpine\nARG B=2\n")
    assert global_args == {"A": "1"}


# ── the global ARG scope ──────────────────────────────────────────────────────
def test_a_global_default_expands_against_the_globals_before_it():
    _plans, global_args = _plan("ARG BASE=alpine\nARG REF=${BASE}:3.20\nFROM $REF\n")
    assert global_args == {"BASE": "alpine", "REF": "alpine:3.20"}


def test_a_global_default_expands_against_the_platform_values():
    plans, global_args = _plan("ARG PLAT=$TARGETOS/$TARGETARCH\nFROM --platform=$PLAT alpine\n")
    assert global_args == {"PLAT": "linux/arm64"}
    assert plans[0].platform == TARGET


def test_a_bare_global_arg_does_not_shadow_a_platform_value():
    # `ARG TARGETARCH` declares a name; it carries no value of its own, so the
    # automatic one has to survive it (Docker resolves a FROM the same way).
    plans, global_args = _plan("ARG TARGETARCH\nFROM --platform=linux/$TARGETARCH alpine\n")
    assert global_args == {}
    assert plans[0].platform == TARGET


def test_a_build_arg_gives_a_bare_global_arg_its_value():
    _plans, global_args = _plan("ARG A\nFROM alpine\n", args={"A": "1"})
    assert global_args == {"A": "1"}


def test_one_global_line_may_declare_several_names():
    _plans, global_args = _plan("ARG A=1 B=2\nFROM $A$B\n")
    assert global_args == {"A": "1", "B": "2"}


def test_a_stage_reference_keeps_the_source_stage_platform():
    plans, _ = _plan(
        "FROM --platform=$BUILDPLATFORM golang AS builder\nFROM --platform=$TARGETPLATFORM builder AS out\n"
    )
    assert [p.platform for p in plans] == [BUILD, BUILD]


def test_a_stage_reference_by_index_keeps_its_platform():
    plans, _ = _plan("FROM --platform=linux/386 alpine\nFROM 0\n")
    assert [p.platform for p in plans] == [Platform("linux", "386")] * 2


def test_a_repeated_platform_flag_keeps_the_last_value():
    plans, _ = _plan("FROM --platform=linux/amd64 --platform=linux/386 alpine\n")
    assert plans[0].platform == Platform("linux", "386")


# ── what a plan refuses ───────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "line",
    [
        "FROM --platform= alpine",
        "FROM --platform alpine",
        "FROM --platform=$NOPE alpine",
        "FROM --platform=linux/sparc alpine",
        "FROM --platform=darwin/amd64 alpine",
        "FROM --platform=linux/arm/v9 alpine",
        "FROM --platform=linux//v7 alpine",
    ],
)
def test_a_platform_that_does_not_resolve_is_refused(line):
    with pytest.raises(BuildError, match="platform"):
        _plan(line + "\n")


def test_only_from_takes_a_platform():
    with pytest.raises(BuildError, match="only FROM"):
        _plan("FROM alpine\nCOPY --platform=linux/amd64 a /b\n")


def test_from_refuses_a_flag_it_does_not_know():
    with pytest.raises(BuildError, match="--chown"):
        _plan("FROM --chown=1000 alpine\n")


def test_a_from_that_does_not_parse_is_refused():
    with pytest.raises(BuildError, match="Invalid FROM"):
        _plan("FROM alpine AS one two\n")


# ── what the engine does with the plan ────────────────────────────────────────
def test_the_engine_builds_each_stage_for_its_own_platform(tmp_path):
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile("FROM --platform=$BUILDPLATFORM scratch AS builder\nFROM scratch\n")

    engine.run(instructions)

    assert [s.platform for s in engine.stages_by_idx] == [BUILD, TARGET]
    assert [s.target_arch_pd for s in engine.stages_by_idx] == ["x86_64", "aarch64"]


def test_a_platform_value_reaches_a_stage_only_once_declared(tmp_path):
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile("FROM scratch\n")
    engine.run(instructions)
    assert "TARGETARCH" not in engine.expansion_scope()

    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile("FROM scratch\nARG TARGETARCH\nARG TARGETVARIANT\n")
    engine.run(instructions)
    scope = engine.expansion_scope()
    assert scope["TARGETARCH"] == "arm64"
    assert scope["TARGETVARIANT"] == ""


def test_a_declared_platform_value_reaches_a_run_step(tmp_path):
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile("FROM scratch\nARG BUILDARCH\n")
    engine.run(instructions)

    assert engine.current.declared_args == {"BUILDARCH"}
    assert engine.current.args["BUILDARCH"] == "amd64"


def test_one_stage_arg_line_declares_several_names(tmp_path):
    engine = _engine(tmp_path)
    _, instructions = parse_dockerfile("FROM scratch\nARG A=1 TARGETARCH B\n")
    engine.run(instructions)

    assert engine.current.declared_args == {"A", "TARGETARCH", "B"}
    assert engine.current.args == {"A": "1", "TARGETARCH": "arm64", "B": ""}


def test_a_pull_records_the_base_image_identity(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    stage = Stage(index=0, name="", rootfs_dir=str(tmp_path), target_arch_pd="aarch64")
    meta = {
        "image_config": {"config": {}, "rootfs": {"diff_ids": ["sha256:d1"]}},
        "manifest": {"_digest": "sha256:m1", "layers": [{"digest": "sha256:l1", "size": 7}]},
    }
    seen = {}

    def fake_pull(image_ref, rootfs_fd, platform):
        seen["platform"] = platform
        return meta

    monkeypatch.setattr(engine_mod, "pull_image", fake_pull)
    engine._pull_base_image(stage, "alpine:3")

    assert seen["platform"] == Platform("linux", "arm64")
    assert stage.base_image_ref == "alpine:3"
    assert stage.base_manifest_digest == "sha256:m1"
    assert stage.layers == [{"digest": "sha256:l1", "size": 7, "diff_id": "sha256:d1"}]


def test_a_non_string_base_digest_is_taken_as_absent(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    stage = Stage(index=0, name="", rootfs_dir=str(tmp_path), target_arch_pd="aarch64")
    monkeypatch.setattr(
        engine_mod,
        "pull_image",
        lambda *_a, **_k: {"image_config": {"config": {}}, "manifest": {"_digest": 5, "layers": []}},
    )

    engine._pull_base_image(stage, "alpine:3")

    assert stage.base_manifest_digest == ""


def test_an_inherited_stage_carries_the_base_identity(tmp_path):
    engine = _engine(tmp_path)
    parent = Stage(index=0, name="p", rootfs_dir=str(tmp_path / "p"), target_arch_pd="aarch64")
    parent.base_image_ref = "alpine:3"
    parent.base_manifest_digest = "sha256:m1"
    child = Stage(index=1, name="c", rootfs_dir=str(tmp_path / "c"), target_arch_pd="aarch64")
    (tmp_path / "c").mkdir()

    engine._inherit_from_stage(child, parent)

    assert child.base_image_ref == "alpine:3"
    assert child.base_manifest_digest == "sha256:m1"
