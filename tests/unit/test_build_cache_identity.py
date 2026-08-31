# What a RUN step's recipe hash has to carry beyond the instruction text. A
# missing input is a layer built for another platform, or against another
# context, served as this step's, and nothing in the build output says so. A
# spurious input costs a rebuild, which is why the equivalent-spelling and
# secret cases are pinned as tightly as the separation ones.

import os
from types import SimpleNamespace

import pytest

from chroot_distro.arch import Platform, parse_platform
from chroot_distro.helpers import build_cache
from chroot_distro.helpers.build_engine import run_step
from chroot_distro.helpers.build_engine.run_mounts import mount_cache_inputs, validate_and_parse_run_flags

TARGET = Platform("linux", "arm64")
BUILD = Platform("linux", "amd64")


def _engine(tmp_path, **kwargs):
    ctx = tmp_path / "ctx"
    ctx.mkdir(exist_ok=True)
    fields = {
        "build_dir": str(ctx),
        "tmp_root": str(tmp_path / "tmp"),
        "target_platform": TARGET,
        "build_platform": BUILD,
        "isolation_mode": "none",
        "stages": {},
        "secrets": {},
        "expansion_scope": dict,
    }
    fields.update(kwargs)
    return SimpleNamespace(**fields)


def _stage(**kwargs):
    fields = {"platform": TARGET, "base_manifest_digest": "sha256:base", "parent_layer_digest": "sha256:parent"}
    fields.update(kwargs)
    return SimpleNamespace(**fields)


def _mounts(*specs):
    return [validate_and_parse_run_flags({"name": "RUN", "flags": {"mount": list(specs)}, "lineno": 1})[0]]


def _inputs(engine, stage, mounts=()):
    return run_step._run_extra_inputs(engine, stage, list(mounts))


# ── platform identity ─────────────────────────────────────────────────────────
def test_two_target_platforms_do_not_share_a_step(tmp_path):
    engine = _engine(tmp_path)
    other = _engine(tmp_path, target_platform=Platform("linux", "386"))

    assert _inputs(engine, _stage()) != _inputs(other, _stage(platform=Platform("linux", "386")))


def test_a_stage_platform_separates_two_stages_on_one_build(tmp_path):
    # The cross-compile shape: both stages belong to the same build, so nothing
    # but the stage platform tells their steps apart.
    engine = _engine(tmp_path)

    assert _inputs(engine, _stage(platform=TARGET)) != _inputs(engine, _stage(platform=BUILD))


def test_an_arm_variant_is_not_the_same_platform(tmp_path):
    engine = _engine(tmp_path)

    plain = _inputs(engine, _stage(platform=Platform("linux", "arm")))
    v7 = _inputs(engine, _stage(platform=Platform("linux", "arm", "v7")))
    assert plain != v7


@pytest.mark.parametrize("spelling", ["linux/amd64", "linux/x86_64", "amd64", "x86_64"])
def test_equivalent_platform_spellings_share_the_entry(tmp_path, spelling):
    engine = _engine(tmp_path, target_platform=Platform("linux", "amd64"))
    spelled = _engine(tmp_path, target_platform=parse_platform(spelling))

    assert _inputs(engine, _stage(platform=Platform("linux", "amd64"))) == _inputs(
        spelled, _stage(platform=parse_platform(spelling))
    )


def test_the_base_manifest_is_part_of_the_step(tmp_path):
    engine = _engine(tmp_path)

    assert _inputs(engine, _stage()) != _inputs(engine, _stage(base_manifest_digest="sha256:other"))


# ── how the step is executed ──────────────────────────────────────────────────
def test_an_emulated_step_is_not_a_native_one(tmp_path):
    native = _engine(tmp_path, build_platform=TARGET)
    emulated = _engine(tmp_path, build_platform=BUILD)

    assert "exec=native" in _inputs(native, _stage())
    assert "exec=emulated" in _inputs(emulated, _stage())


def test_the_isolation_mode_is_part_of_the_step(tmp_path):
    plain = _engine(tmp_path)
    isolated = _engine(tmp_path, isolation_mode="max")

    assert _inputs(plain, _stage()) != _inputs(isolated, _stage())


# ── what a --mount exposes ────────────────────────────────────────────────────
def test_a_bound_context_file_changes_the_step(tmp_path):
    engine = _engine(tmp_path)
    src = tmp_path / "ctx" / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    mounts = _mounts("type=bind,source=src,target=/src")

    before = _inputs(engine, _stage(), mounts)
    (src / "main.c").write_text("int main(void) { return 1; }\n")

    assert _inputs(engine, _stage(), mounts) != before


def test_a_file_outside_the_bound_subtree_does_not(tmp_path):
    engine = _engine(tmp_path)
    (tmp_path / "ctx" / "src").mkdir()
    (tmp_path / "ctx" / "src" / "main.c").write_text("x\n")
    mounts = _mounts("type=bind,source=src,target=/src")

    before = _inputs(engine, _stage(), mounts)
    (tmp_path / "ctx" / "elsewhere.txt").write_text("y\n")

    assert _inputs(engine, _stage(), mounts) == before


def test_a_bind_from_a_stage_is_identified_by_that_stage_tree(tmp_path):
    builder = _stage(parent_layer_digest="sha256:built")
    engine = _engine(tmp_path, stages={"builder": builder})
    mounts = _mounts("type=bind,from=builder,source=/out,target=/out")

    assert mount_cache_inputs(engine, mounts) == ["mount 0 /out stage=sha256:built"]
    builder.parent_layer_digest = "sha256:rebuilt"
    assert mount_cache_inputs(engine, mounts) == ["mount 0 /out stage=sha256:rebuilt"]


def test_a_bind_from_an_image_is_identified_without_pulling_it(tmp_path):
    # Resolving the tree would mean fetching the image, and answering what a step
    # is must not need a network round trip on the way to a cache hit.
    engine = _engine(tmp_path)
    mounts = _mounts("type=bind,from=alpine:3,source=/lib,target=/lib")

    assert mount_cache_inputs(engine, mounts) == ["mount 0 /lib image=alpine:3"]


def test_a_cache_mount_and_a_secret_are_not_inputs(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("first")
    engine = _engine(tmp_path, secrets={"tok": str(secret)})
    mounts = [
        *_mounts("type=cache,target=/root/.cache"),
        *_mounts("type=secret,id=tok"),
        *_mounts("type=tmpfs,target=/tmp"),
    ]

    before = _inputs(engine, _stage(), mounts)
    secret.write_text("second")

    assert mount_cache_inputs(engine, mounts) == []
    assert _inputs(engine, _stage(), mounts) == before
    assert "first" not in before and "second" not in before


# ── the source digest itself ──────────────────────────────────────────────────
def test_a_tree_digest_follows_content_and_not_timestamps(tmp_path):
    tree = tmp_path / "tree"
    (tree / "pkg").mkdir(parents=True)
    (tree / "pkg" / "a.txt").write_text("one")
    before = build_cache.source_digest(str(tree))

    os.utime(tree / "pkg" / "a.txt", (1, 1))
    assert build_cache.source_digest(str(tree)) == before

    (tree / "pkg" / "a.txt").write_text("two")
    assert build_cache.source_digest(str(tree)) != before


def test_a_tree_digest_notices_a_rename_a_deletion_and_a_mode(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("same")
    original = build_cache.source_digest(str(tree))

    (tree / "a.txt").rename(tree / "b.txt")
    renamed = build_cache.source_digest(str(tree))
    assert renamed != original

    os.chmod(tree / "b.txt", 0o700)
    assert build_cache.source_digest(str(tree)) != renamed

    (tree / "b.txt").unlink()
    assert build_cache.source_digest(str(tree)) != renamed


def test_a_single_file_source_digests_its_content(tmp_path):
    path = tmp_path / "script.sh"
    path.write_text("echo one\n")
    before = build_cache.source_digest(str(path))

    path.write_text("echo two\n")
    assert build_cache.source_digest(str(path)) != before


def test_a_missing_source_digests_as_nothing(tmp_path):
    assert build_cache.source_digest(str(tmp_path / "nope")) == build_cache.source_digest(str(tmp_path / "also-nope"))
