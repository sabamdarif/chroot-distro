# What `build --export` accepts and how it dispatches. Only `type=local` and
# `type=tar` are taken, a destination that already exists is refused before the
# locks, and an export runs after the solve, once per destination, against the
# host's platform.

import os
from types import SimpleNamespace

import pytest

from chroot_distro import paths
from chroot_distro.arch import Platform
from chroot_distro.commands import build as build_cmd

AMD64 = Platform("linux", "amd64")
ARM64 = Platform("linux", "arm64")


def _result(platform):
    return SimpleNamespace(
        platform=platform,
        manifest={"config": {"digest": "sha256:" + "0" * 64}},
        image_config={"architecture": platform.architecture, "os": platform.os},
        layers=[{"size": 4096, "digest": "sha256:" + "1" * 64, "diff_id": "sha256:" + "2" * 64}],
        step_recipes=frozenset(),
    )


@pytest.fixture
def run(monkeypatch, tmp_path):
    """Run `command_build` with the locks, the scratch tree and the solve stubbed."""
    ctx = tmp_path / "ctx"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM alpine\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    containers = tmp_path / "containers"
    containers.mkdir()
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(containers))

    seen = SimpleNamespace(exports=[], locks=[])

    class _Lock:
        def __init__(self, image_ref, arch, command="build"):
            self.lock_path = f"{image_ref}/{arch}"

        def __enter__(self):
            seen.locks.append(self.lock_path)
            return self

        def __exit__(self, *_exc):
            return False

    def _solve(_request, platforms):
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
    monkeypatch.setattr(build_cmd, "ensure_handler", lambda arch: (f"/usr/bin/qemu-{arch}", ""))
    monkeypatch.setattr(build_cmd, "solve_platforms", _solve)
    monkeypatch.setattr(build_cmd, "store_in_cache", lambda *_a: None)
    monkeypatch.setattr(build_cmd, "write_rootfs_tar", lambda dest, *a: seen.exports.append(("tar", dest)))
    monkeypatch.setattr(build_cmd, "export_local_dir", lambda dest, *a: seen.exports.append(("local", dest)))

    def _run(**kwargs):
        kwargs.setdefault("path", str(ctx))
        kwargs.setdefault("tags", ["img:1"])
        kwargs.setdefault("quiet", True)
        build_cmd.command_build(SimpleNamespace(**kwargs))
        return seen

    _run.seen = seen
    _run.tmp = tmp_path
    return _run


def test_no_export_runs_nothing(run):
    assert run().exports == []


def test_a_tar_and_a_local_export_each_run_once(run, tmp_path):
    seen = run(exports=[f"type=tar,dest={tmp_path / 'r.tar'}", f"type=local,dest={tmp_path / 'dir'}"])
    assert seen.exports == [("tar", str(tmp_path / "r.tar")), ("local", str(tmp_path / "dir"))]


@pytest.mark.parametrize(
    "spec",
    ["type=registry,ref=x", "/plain/path", "dest=/dir", "type=tar", "type=tar,dest=", "type=tar,dest=/f,mode=max"],
)
def test_an_unsupported_spec_is_refused_before_the_locks(run, capsys, spec):
    with pytest.raises(SystemExit):
        run(exports=[spec])
    assert "--export" in capsys.readouterr().err
    assert run.seen.locks == []


def test_an_existing_destination_is_refused_before_the_locks(run, capsys, tmp_path):
    occupied = tmp_path / "occupied"
    occupied.write_text("here")
    with pytest.raises(SystemExit):
        run(exports=[f"type=tar,dest={occupied}"])
    assert "already exists" in capsys.readouterr().err
    assert run.seen.locks == []
