# What `build --cache-from` and `--cache-to` accept, and where in the command they
# happen. The directory format itself is `test_build_cache_io.py`; what matters
# here is the wiring: only `type=local` is taken, a bad spec is refused before the
# locks, the import runs under the locks and ahead of the solve so every step it
# carries can be served, and the export sees one set of recipes for the whole
# matrix.

import os
from types import SimpleNamespace

import pytest

from chroot_distro import paths
from chroot_distro.arch import Platform
from chroot_distro.commands import build as build_cmd

AMD64 = Platform("linux", "amd64")
ARM64 = Platform("linux", "arm64")


def _result(platform, recipes):
    return SimpleNamespace(
        platform=platform,
        manifest={"config": {"digest": "sha256:" + "0" * 64}},
        image_config={"architecture": platform.architecture, "os": platform.os},
        layers=[{"size": 4096, "digest": "sha256:" + "1" * 64, "diff_id": "sha256:" + "2" * 64}],
        step_recipes=frozenset(recipes),
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

    seen = SimpleNamespace(order=[], locks=[], imported=[], exported=[], recipes=None)
    recipes = {"a" * 64: None}

    class _Lock:
        def __init__(self, image_ref, arch, command="build"):
            self.lock_path = f"{image_ref}/{arch}"

        def __enter__(self):
            seen.order.append("lock")
            seen.locks.append(self.lock_path)
            return self

        def __exit__(self, *_exc):
            seen.order.append("unlock")
            return False

    def _solve(_request, platforms):
        seen.order.append("solve")
        return [_result(platform, recipes) for platform in platforms]

    def _import(path):
        seen.order.append("import")
        seen.imported.append(path)
        return 3, 0

    def _export(path, asked):
        seen.exported.append(path)
        seen.recipes = set(asked)
        return 3, 4096

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
    monkeypatch.setattr(build_cmd, "import_cache", _import)
    monkeypatch.setattr(build_cmd, "export_cache", _export)

    def _run(**kwargs):
        kwargs.setdefault("path", str(ctx))
        kwargs.setdefault("tags", ["img:1"])
        kwargs.setdefault("quiet", True)
        build_cmd.command_build(SimpleNamespace(**kwargs))
        return seen

    _run.seen = seen
    _run.recipes = recipes
    _run.tmp = tmp_path
    return _run


# ── what the options accept ───────────────────────────────────────────────────


def test_neither_option_touches_a_cache_directory(run):
    seen = run()
    assert (seen.imported, seen.exported) == ([], [])


def test_a_local_directory_is_imported_and_exported(run, tmp_path):
    seen = run(
        cache_from=[f"type=local,src={tmp_path / 'in'}"],
        cache_to=[f"type=local,dest={tmp_path / 'out'}"],
    )
    assert seen.imported == [str(tmp_path / "in")]
    assert seen.exported == [str(tmp_path / "out")]


def test_both_options_are_repeatable_and_deduplicated(run, tmp_path):
    seen = run(
        cache_from=[f"type=local,src={tmp_path / 'a'}", f"type=local,src={tmp_path / 'a'}"],
        cache_to=[f"type=local,dest={tmp_path / 'b'}", f"type=local,dest={tmp_path / 'c'}"],
    )
    assert seen.imported == [str(tmp_path / "a")]
    assert seen.exported == [str(tmp_path / "b"), str(tmp_path / "c")]


def test_a_relative_directory_is_resolved_once(run, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert run(cache_to=["type=local,dest=./out"]).exported == [str(tmp_path / "out")]


# ── what they refuse, and when ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spec",
    [
        "type=registry,ref=docker.io/me/cache",
        "type=gha",
        "/plain/path",
        "src=/dir",
        "type=local",
        "type=local,src=",
        "type=local,src=/dir,mode=max",
        "type=local,dest=/dir",
    ],
)
def test_a_spec_this_program_cannot_honour_is_refused_before_the_locks(run, capsys, spec):
    with pytest.raises(SystemExit) as exc:
        run(cache_from=[spec])

    assert exc.value.code == 1
    assert "--cache-from" in capsys.readouterr().err
    assert run.seen.locks == []


def test_a_cache_to_dest_that_is_a_file_is_refused_before_the_locks(run, capsys, tmp_path):
    occupied = tmp_path / "occupied"
    occupied.write_text("not a directory")

    with pytest.raises(SystemExit) as exc:
        run(cache_to=[f"type=local,dest={occupied}"])

    assert exc.value.code == 1
    assert "--cache-to" in capsys.readouterr().err
    assert run.seen.locks == []


# ── where in the build each one happens ───────────────────────────────────────


def test_the_import_is_held_under_the_locks_and_runs_before_the_solve(run, tmp_path):
    seen = run(cache_from=[f"type=local,src={tmp_path / 'in'}"])
    assert seen.order == ["lock", "import", "solve", "unlock"]
    assert seen.locks == ["img:1/x86_64"]


def test_no_cache_leaves_nothing_to_serve_so_nothing_is_imported(run, capsys, tmp_path):
    seen = run(cache_from=[f"type=local,src={tmp_path / 'in'}"], no_cache=True, quiet=False)

    assert seen.imported == []
    assert "--no-cache" in capsys.readouterr().err


def test_no_cache_still_exports_what_the_build_rebuilt(run, tmp_path):
    seen = run(cache_to=[f"type=local,dest={tmp_path / 'out'}"], no_cache=True)
    assert seen.exported == [str(tmp_path / "out")]


def test_one_matrix_exports_one_set_of_steps(run, tmp_path):
    seen = run(platforms=["linux/amd64,linux/arm64"], cache_to=[f"type=local,dest={tmp_path / 'out'}"])

    assert seen.exported == [str(tmp_path / "out")]
    assert seen.recipes == set(run.recipes)


def test_an_import_that_cannot_be_read_ends_the_build(run, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(build_cmd, "import_cache", lambda _p: (_ for _ in ()).throw(ValueError("not an index")))

    with pytest.raises(SystemExit) as exc:
        run(cache_from=[f"type=local,src={tmp_path / 'in'}"])

    assert exc.value.code == 1
    assert "not an index" in capsys.readouterr().err
    assert "solve" not in run.seen.order


def test_an_export_that_cannot_be_written_ends_the_build(run, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(build_cmd, "export_cache", lambda _p, _r: (_ for _ in ()).throw(OSError(13, "denied")))

    with pytest.raises(SystemExit) as exc:
        run(cache_to=[f"type=local,dest={tmp_path / 'out'}"])

    assert exc.value.code == 1
    assert "Cannot export the build cache" in capsys.readouterr().err


def test_a_refused_entry_is_reported_and_the_build_carries_on(run, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(build_cmd, "import_cache", lambda _p: (1, 2))

    seen = run(cache_from=[f"type=local,src={tmp_path / 'in'}"], quiet=False)

    assert "solve" in seen.order
    err = capsys.readouterr().err
    assert "Ignored 2 cache entries" in err
    assert "Imported 1 cached step(s)" in err
