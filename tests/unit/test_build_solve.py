# The boundary around one solve: what a request produces, and what it leaves.
#
# One engine invocation, one platform result. Two requests run one after the
# other must share no scratch tree, no stage map and no reporter, because the
# next platform of a matrix is solved under the same build scratch root as the
# one before it: a tree, or a step number, that outlives its own solve is state
# the second platform would inherit from the first.

import dataclasses
import hashlib
import json
import os

import pytest

from chroot_distro import dirfd
from chroot_distro.arch import Platform
from chroot_distro.helpers.build_engine import BuildRequest, solve_platform
from chroot_distro.helpers.build_engine import solve as solve_mod
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.docker.media import canonical_json
from chroot_distro.helpers.dockerfile import parse_dockerfile

ARM64 = Platform("linux", "arm64")
AMD64 = Platform("linux", "amd64")


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
    kwargs.setdefault("target_platform", ARM64)
    kwargs.setdefault("quiet", True)
    return BuildRequest(
        build_dir=str(context),
        instructions=instructions,
        build_platform=AMD64,
        scratch_dir=str(root),
        scratch_fd=fd,
        **kwargs,
    )


# ── one request, one result ───────────────────────────────────────────────────
def test_a_solve_answers_for_its_own_platform(scratch, context):
    result = solve_platform(_request(scratch, context, "FROM scratch\nENV A=1\n"))

    assert result.platform == ARM64
    assert result.image_config["architecture"] == "arm64"
    assert result.image_config["os"] == "linux"
    assert result.layers == []
    assert result.manifest["layers"] == []
    # The manifest describes the exact config bytes a caller would publish.
    config_bytes = canonical_json(result.image_config)
    assert result.manifest["config"]["digest"] == "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    assert result.manifest["config"]["size"] == len(config_bytes)


def test_the_solve_tree_goes_with_the_solve(scratch, context, engines):
    root, _fd = scratch

    solve_platform(_request(scratch, context, "FROM scratch\n"))

    assert engines[0].tmp_root.startswith(str(root) + os.sep)
    assert not os.path.exists(engines[0].tmp_root)
    assert os.listdir(str(root)) == []

# ── two solves, one after the other ───────────────────────────────────────────
def test_two_sequential_solves_share_nothing(scratch, context, engines):
    root, _fd = scratch
    first_request = _request(scratch, context, "FROM scratch\nENV A=1\n")

    first = solve_platform(first_request)
    second = solve_platform(dataclasses.replace(first_request, target_platform=AMD64))

    assert (first.platform, second.platform) == (ARM64, AMD64)
    assert [r.image_config["architecture"] for r in (first, second)] == ["arm64", "amd64"]
    assert engines[0].tmp_root != engines[1].tmp_root
    assert engines[0].reporter is not engines[1].reporter
    assert engines[0].stages_by_idx and engines[1].stages_by_idx
    assert engines[0].stages_by_idx[0] is not engines[1].stages_by_idx[0]
    assert os.listdir(str(root)) == []


def test_each_solve_numbers_its_own_steps(scratch, context, capsys):
    request = _request(scratch, context, "FROM scratch\nENV A=1\n", quiet=False, progress="rawjson")

    solve_platform(request)
    solve_platform(request)

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [ev["step_no"] for ev in events if ev["kind"] == "step_started"] == [1, 2, 1, 2]


def test_one_parse_answers_for_every_solve(scratch, context):
    request = _request(scratch, context, "FROM scratch\nENV A=1\nARG B=2\n")
    before = json.dumps(request.instructions, sort_keys=True)

    solve_platform(request)

    assert json.dumps(request.instructions, sort_keys=True) == before


# ── a solve that fails ────────────────────────────────────────────────────────
def test_a_failed_solve_leaves_the_root_as_it_found_it(scratch, context):
    root, _fd = scratch

    with pytest.raises(BuildError, match="not found in build context"):
        solve_platform(_request(scratch, context, "FROM scratch\nCOPY nope /x\n"))

    assert os.listdir(str(root)) == []
    # And the next platform still builds under the same root.
    assert solve_platform(_request(scratch, context, "FROM scratch\n")).platform == ARM64


