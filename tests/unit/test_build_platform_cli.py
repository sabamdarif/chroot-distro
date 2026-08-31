# What `build --platform` asks for, and what the rest of the command does with it.
#
# The list reaches the coordinator in the order it was written, with one entry
# per platform however it was spelled, and everything a build publishes is
# per platform after it: one lock and one manifest cache entry per (tag,
# platform), one archive holding all of them, and one container for the one
# platform `--install-as` can pick. What cannot be built is refused before the
# locks and the scratch tree, which is the promise the rest of the command's
# validation already makes.

import os
from types import SimpleNamespace

import pytest

from chroot_distro import paths
from chroot_distro.arch import Platform, parse_platform
from chroot_distro.commands import build as build_cmd

AMD64 = Platform("linux", "amd64")
ARM64 = Platform("linux", "arm64")
ARMV7 = parse_platform("linux/arm/v7")


def _result(platform):
    """A finished solve, as much of one as the publishing below reads."""
    return SimpleNamespace(
        platform=platform,
        manifest={"config": {"digest": "sha256:" + "0" * 64}},
        image_config={"architecture": platform.architecture, "os": platform.os},
        layers=[{"size": 4096, "digest": "sha256:" + "1" * 64, "diff_id": "sha256:" + "2" * 64}],
    )


@pytest.fixture
def run(monkeypatch, tmp_path):
    """Run `command_build` with the locks, the scratch tree and the solve stubbed.

    The host is an amd64 machine that emulates nothing, so what a test asks for
    is the only thing deciding the outcome.
    """
    ctx = tmp_path / "ctx"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM alpine\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    containers = tmp_path / "containers"
    containers.mkdir()
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(containers))

    seen = SimpleNamespace(locks=[], asked=None, emulators=[], cached=[], archives=[], installed=None)

    class _Lock:
        def __init__(self, image_ref, arch, command="build"):
            seen.locks.append((image_ref, arch))
            self.lock_path = f"{image_ref}/{arch}"

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def _emulator(arch):
        seen.emulators.append(arch)
        return f"/usr/bin/qemu-{arch}", ""

    def _solve(_request, platforms):
        seen.asked = list(platforms)
        return [_result(platform) for platform in platforms]

    monkeypatch.setattr(build_cmd, "BuildLock", _Lock)
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
    monkeypatch.setattr(build_cmd, "get_device_platform", lambda: AMD64)
    monkeypatch.setattr(build_cmd, "needs_emulation", lambda arch: arch != "x86_64")
    monkeypatch.setattr(build_cmd, "ensure_handler", _emulator)
    monkeypatch.setattr(build_cmd, "solve_platforms", _solve)
    monkeypatch.setattr(
        build_cmd,
        "store_in_cache",
        lambda tag, platform, _manifest, _config: seen.cached.append((tag, str(platform))),
    )
    monkeypatch.setattr(
        build_cmd,
        "write_oci_archive",
        lambda path, results, ref: seen.archives.append((path, [str(r.platform) for r in results], ref)),
    )
    monkeypatch.setattr(
        build_cmd,
        "_install_as_container",
        lambda name, _ref, arch, _quiet: setattr(seen, "installed", (name, arch)),
    )

    def _run(dockerfile=None, **kwargs):
        if dockerfile is not None:
            (ctx / "Dockerfile").write_text(dockerfile)
        kwargs.setdefault("path", str(ctx))
        kwargs.setdefault("tags", ["img:1"])
        kwargs.setdefault("quiet", True)
        build_cmd.command_build(SimpleNamespace(**kwargs))
        return seen

    _run.seen = seen
    return _run


# ── what the option resolves to ───────────────────────────────────────────────
def test_no_platform_option_builds_for_the_host(run):
    assert run().asked == [AMD64]


def test_a_comma_separated_list_is_one_target_each(run):
    assert run(platforms=["linux/amd64,linux/arm64"]).asked == [AMD64, ARM64]


def test_the_option_is_repeatable(run):
    assert run(platforms=["linux/arm64", "linux/arm/v7"]).asked == [ARM64, ARMV7]


def test_two_spellings_of_one_platform_are_one_target(run):
    assert run(platforms=["linux/arm64,linux/aarch64"]).asked == [ARM64]


def test_the_first_mention_of_a_platform_keeps_its_place(run):
    assert run(platforms=["linux/arm64,linux/amd64,linux/arm64"]).asked == [ARM64, AMD64]


def test_an_alias_is_normalized_before_it_is_used(run):
    # linux/arm carries v7 because that is the arm this program builds for, so
    # the platform an index describes says so as well.
    assert run(platforms=["linux/x86_64,linux/arm"]).asked == [AMD64, ARMV7]


# ── what it refuses, and when ─────────────────────────────────────────────────
@pytest.mark.parametrize(
    "value",
    ["linux//arm64", "windows/amd64", "linux/amd64,", "linux/sparc64", "linux/arm/v9"],
)
def test_a_platform_this_program_cannot_build_is_refused_before_the_locks(run, capsys, value):
    with pytest.raises(SystemExit) as exc:
        run(platforms=[value])

    assert exc.value.code == 1
    assert "--platform" in capsys.readouterr().err
    assert run.seen.locks == []


def test_architecture_alone_still_names_one_platform(run):
    assert run(override_arch="aarch64").asked == [ARM64]


def test_architecture_and_platform_may_name_the_same_platform(run):
    assert run(override_arch="aarch64", platforms=["linux/arm64"]).asked == [ARM64]


def test_architecture_and_platform_naming_different_platforms_is_refused(run, capsys):
    with pytest.raises(SystemExit):
        run(override_arch="aarch64", platforms=["linux/amd64"])

    assert "name different platforms" in capsys.readouterr().err
    assert run.seen.locks == []


def test_architecture_cannot_stand_for_a_matrix(run, capsys):
    with pytest.raises(SystemExit):
        run(override_arch="aarch64", platforms=["linux/arm64,linux/amd64"])

    assert "name different platforms" in capsys.readouterr().err


# ── what a matrix does to the rest of the command ─────────────────────────────
def test_one_lock_per_tag_and_platform(run):
    seen = run(tags=["one:1", "two:2"], platforms=["linux/amd64,linux/arm64"])

    assert sorted(seen.locks) == [
        ("one:1", "aarch64"),
        ("one:1", "x86_64"),
        ("two:2", "aarch64"),
        ("two:2", "x86_64"),
    ]


def test_every_tag_records_every_platform(run):
    seen = run(tags=["one:1", "two:2"], platforms=["linux/amd64,linux/arm64"])

    assert seen.cached == [
        ("one:1", "linux/amd64"),
        ("one:1", "linux/arm64"),
        ("two:2", "linux/amd64"),
        ("two:2", "linux/arm64"),
    ]


def test_one_archive_holds_every_platform(run, tmp_path):
    out = tmp_path / "img.tar"

    seen = run(platforms=["linux/amd64,linux/arm64"], outputs=[str(out)])

    assert seen.archives == [(str(out), ["linux/amd64", "linux/arm64"], "img:1")]


def test_each_platform_of_a_matrix_gets_its_own_emulator_answer(run):
    # The stage plan is per target platform, so the preflight asks once per
    # foreign platform and not once per Dockerfile.
    seen = run(dockerfile="FROM alpine\nRUN echo hi\n", platforms=["linux/arm64,linux/riscv64,linux/amd64"])

    assert seen.emulators == ["aarch64", "riscv64"]


def test_a_stage_that_does_not_resolve_names_the_platform_it_failed_for(run, capsys):
    # `linux/arm/$TARGETVARIANT` resolves for the arm/v7 target and for no
    # other: every other platform's variant is empty, which leaves a malformed
    # platform string behind.
    with pytest.raises(SystemExit):
        run(
            dockerfile="FROM --platform=linux/arm/$TARGETVARIANT alpine\n",
            platforms=["linux/arm/v7,linux/amd64"],
        )

    err = capsys.readouterr().err
    assert "target platform 'linux/amd64'" in err
    assert run.seen.locks == []


# ── which platform a container is installed from ──────────────────────────────
def test_install_as_takes_the_host_platform_out_of_a_matrix(run):
    seen = run(platforms=["linux/arm64,linux/amd64"], install_as="mine")

    assert seen.installed == ("mine", "x86_64")


def test_install_as_takes_a_platform_the_host_runs_natively(run, monkeypatch):
    # 32-bit userspace on a 64-bit CPU of the same family is not emulation, so
    # linux/386 is a container this amd64 host can actually enter.
    monkeypatch.setattr(build_cmd, "needs_emulation", lambda arch: arch not in ("x86_64", "i686"))

    seen = run(platforms=["linux/riscv64,linux/386"], install_as="mine")

    assert seen.installed == ("mine", "i686")


def test_install_as_still_installs_one_foreign_platform(run):
    seen = run(platforms=["linux/arm64"], install_as="mine")

    assert seen.installed == ("mine", "aarch64")


def test_install_as_refuses_a_matrix_this_host_cannot_run(run, capsys):
    with pytest.raises(SystemExit):
        run(platforms=["linux/arm64,linux/riscv64"], install_as="mine")

    err = capsys.readouterr().err
    assert "none of them runs on this 'linux/amd64' host" in err
    assert run.seen.locks == []
