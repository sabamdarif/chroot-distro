# A list of target platforms in, one result per platform out.
#
# The order the caller asked in is the order an image index will describe, so it
# is the coordinator's to keep; two spellings of one platform are one solve,
# because an index that named a platform twice is not a valid one. A platform
# that fails takes the build with it: half a matrix must never reach the caller
# as a result it could publish.

import json
import os

import pytest

from chroot_distro import dirfd
from chroot_distro.arch import Platform, parse_platform
from chroot_distro.helpers.build_engine import BuildRequest, solve_platforms
from chroot_distro.helpers.build_engine import solve as solve_mod
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.dockerfile import parse_dockerfile

AMD64 = Platform("linux", "amd64")
ARM64 = Platform("linux", "arm64")
ARMV7 = Platform("linux", "arm", "v7")


@pytest.fixture
def scratch(tmp_path):
    """A build's scratch root and a descriptor on it, as `build` opens one."""
    root = tmp_path / "scratch"
    root.mkdir()
    fd = dirfd.opendir(str(root))
    try:
        yield root, fd
    finally:
        os.close(fd)


@pytest.fixture
def context(tmp_path):
    d = tmp_path / "ctx"
    d.mkdir()
    return d


@pytest.fixture
def engines(monkeypatch):
    """Every engine the solves under test build, in order."""
    made = []
    real = solve_mod.BuildEngine

    def spy(**kwargs):
        engine = real(**kwargs)
        made.append(engine)
        return engine

    monkeypatch.setattr(solve_mod, "BuildEngine", spy)
    return made


def _request(scratch, context, text, **kwargs):
    root, fd = scratch
    _, instructions = parse_dockerfile(text)
    kwargs.setdefault("target_platform", AMD64)
    kwargs.setdefault("quiet", True)
    return BuildRequest(
        build_dir=str(context),
        instructions=instructions,
        build_platform=AMD64,
        scratch_dir=str(root),
        scratch_fd=fd,
        **kwargs,
    )


# ── how many platforms were asked for ─────────────────────────────────────────
def test_one_platform_is_one_result(scratch, context):
    results = solve_platforms(_request(scratch, context, "FROM scratch\n"), [ARM64])

    assert [r.platform for r in results] == [ARM64]
    assert results[0].image_config["architecture"] == "arm64"


def test_two_platforms_keep_the_order_they_were_asked_in(scratch, context, engines):
    root, _fd = scratch

    results = solve_platforms(_request(scratch, context, "FROM scratch\nENV A=1\n"), [ARM64, AMD64])

    assert [r.platform for r in results] == [ARM64, AMD64]
    assert [r.image_config["architecture"] for r in results] == ["arm64", "amd64"]
    # One engine and one tree per platform, and nothing left under the root.
    assert engines[0].tmp_root != engines[1].tmp_root
    assert os.listdir(str(root)) == []


def test_a_platform_named_twice_is_solved_once(scratch, context, engines):
    results = solve_platforms(_request(scratch, context, "FROM scratch\n"), [ARM64, AMD64, ARM64])

    assert [r.platform for r in results] == [ARM64, AMD64]
    assert len(engines) == 2


def test_two_spellings_of_one_platform_are_one_solve(scratch, context, engines):
    asked = [parse_platform("linux/arm64"), parse_platform("linux/aarch64"), parse_platform("linux/arm/v7")]

    results = solve_platforms(_request(scratch, context, "FROM scratch\n"), asked)

    assert [r.platform for r in results] == [ARM64, ARMV7]
    assert len(engines) == 2


def test_no_platform_is_a_build_error(scratch, context):
    with pytest.raises(BuildError, match="no target platform"):
        solve_platforms(_request(scratch, context, "FROM scratch\n"), [])


# ── what each solve is told it is ─────────────────────────────────────────────
def test_a_matrix_names_the_platform_on_every_event(scratch, context, capsys):
    request = _request(scratch, context, "FROM scratch\nENV A=1\n", quiet=False, progress="rawjson")

    solve_platforms(request, [ARM64, AMD64])

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {ev["platform"] for ev in events} == {"linux/arm64", "linux/amd64"}


def test_one_platform_names_none(scratch, context, capsys):
    request = _request(scratch, context, "FROM scratch\nENV A=1\n", quiet=False, progress="rawjson")

    solve_platforms(request, [ARM64])

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {ev["platform"] for ev in events} == {""}


# ── one platform fails ────────────────────────────────────────────────────────
def test_a_failing_platform_ends_the_matrix(scratch, context, engines):
    # `--platform=linux/arm/$TARGETVARIANT` resolves for the arm/v7 target and
    # for no other: every other platform's variant is empty, which leaves a
    # malformed platform string behind.
    root, _fd = scratch
    request = _request(scratch, context, "FROM --platform=linux/arm/$TARGETVARIANT scratch\n")

    with pytest.raises(BuildError, match="target platform 'linux/amd64': .*malformed platform"):
        solve_platforms(request, [ARMV7, AMD64, ARM64])

    # The third platform was never started, and the tree of the one that
    # succeeded is gone along with the failed one's.
    assert len(engines) == 2
    assert os.listdir(str(root)) == []


def test_one_platform_reports_its_failure_unqualified(scratch, context):
    request = _request(scratch, context, "FROM scratch\nCOPY nope /x\n")

    with pytest.raises(BuildError) as caught:
        solve_platforms(request, [ARM64])

    assert "target platform" not in str(caught.value)
