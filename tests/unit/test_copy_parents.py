import os
from unittest.mock import patch

import pytest

from chroot_distro.helpers.build_engine import copy_step
from chroot_distro.helpers.build_engine.copy_step import (
    _do_copy_or_add,
    _parents_dest,
    _split_parents_pivot,
)
from chroot_distro.helpers.build_engine.errors import BuildError


# ── pivot splitting ───────────────────────────────────────────────────────────
def test_split_no_pivot():
    assert _split_parents_pivot("src/a.py") == ("src/a.py", "")


def test_split_pivot():
    assert _split_parents_pivot("src/./lib/*.py") == ("src/lib/*.py", "src")


def test_split_pivot_nested_anchor():
    assert _split_parents_pivot("a/b/./c") == ("a/b/c", "a/b")


def test_parents_dest_no_anchor():
    assert _parents_dest("/app/", "src/a.py", "") == "/app/src/a.py"


def test_parents_dest_with_anchor():
    assert _parents_dest("/app", "src/lib/a.py", "src") == "/app/lib/a.py"


def test_parents_dest_outside_anchor_rejected():
    with pytest.raises(BuildError, match=r"outside its /\./ pivot"):
        _parents_dest("/app", "other/a.py", "src")


# ── _do_copy_or_add integration (real files, tmp rootfs) ─────────────────────
class _Stage:
    def __init__(self, base):
        self.rootfs_dir = str(base / "rootfs")
        self.rootfs_fd = None
        self.workdir = "/"
        self.layers = []
        self.parent_layer_digest = None
        self.index = 0
        os.makedirs(self.rootfs_dir, exist_ok=True)


class _Engine:
    def __init__(self, base):
        self.build_dir = str(base / "ctx")
        self.tmp_root = str(base / "tmp")
        self.ignore_patterns = []
        self.stages = {}
        self.quiet = True
        self.current = _Stage(base)
        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(self.tmp_root, exist_ok=True)


@pytest.fixture
def engine(tmp_path, monkeypatch):
    eng = _Engine(tmp_path)
    layer_dir = tmp_path / "layers"
    layer_dir.mkdir()
    monkeypatch.setattr(
        copy_step, "layer_cache_path", lambda digest: str(layer_dir / digest.replace(":", "_"))
    )
    return eng


def _write(engine, rel, content="x"):
    path = os.path.join(engine.build_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def _copy(engine, value, flags=None, name="COPY"):
    instr = {
        "name": name,
        "flags": flags or {},
        "value": value,
        "exec_form": False,
        "heredocs": [],
        "lineno": 3,
    }
    _do_copy_or_add(engine, instr, allow_url=False, auto_extract=False)


def _rootfs_has(engine, rel):
    return os.path.isfile(os.path.join(engine.current.rootfs_dir, rel))


def test_parents_preserves_structure_for_glob(engine):
    _write(engine, "src/a/one.py")
    _write(engine, "src/b/two.py")
    _copy(engine, "src/*/*.py /app/", flags={"parents": ""})
    assert _rootfs_has(engine, "app/src/a/one.py")
    assert _rootfs_has(engine, "app/src/b/two.py")


def test_without_parents_glob_flattens(engine):
    _write(engine, "src/a/one.py")
    _write(engine, "src/b/two.py")
    _copy(engine, "src/*/*.py /app/")
    assert _rootfs_has(engine, "app/one.py")
    assert _rootfs_has(engine, "app/two.py")


def test_parents_pivot_anchors_preserved_path(engine):
    _write(engine, "src/lib/deep/mod.py")
    _copy(engine, "src/./lib/deep/mod.py /app/", flags={"parents": ""})
    assert _rootfs_has(engine, "app/lib/deep/mod.py")
    assert not _rootfs_has(engine, "app/src/lib/deep/mod.py")


def test_parents_exact_file_without_pivot_is_context_relative(engine):
    _write(engine, "src/a.py")
    _copy(engine, "src/a.py /app/", flags={"parents": ""})
    assert _rootfs_has(engine, "app/src/a.py")


def test_parents_directory_source(engine):
    _write(engine, "src/pkg/mod.py")
    _copy(engine, "src/pkg /app/", flags={"parents": ""})
    assert _rootfs_has(engine, "app/src/pkg/mod.py")


def test_parents_with_chmod(engine):
    _write(engine, "src/a.py")
    _copy(engine, "src/a.py /app/", flags={"parents": "", "chmod": "600"})
    target = os.path.join(engine.current.rootfs_dir, "app/src/a.py")
    assert oct(os.stat(target).st_mode & 0o777) == "0o600"


def test_parents_from_stage_rootfs(engine, tmp_path):
    other = tmp_path / "other-rootfs"
    os.makedirs(other / "opt" / "tool", exist_ok=True)
    (other / "opt" / "tool" / "bin.sh").write_text("#!/bin/sh\n")

    class _Ref:
        rootfs_dir = str(other)
        rootfs_fd = None

    engine.stages["builder"] = _Ref()
    _copy(engine, "/opt/./tool/bin.sh /dst/", flags={"parents": "", "from": "builder"})
    assert _rootfs_has(engine, "dst/tool/bin.sh")


# ── flag whitelist ────────────────────────────────────────────────────────────
def test_link_still_rejected(engine):
    _write(engine, "a")
    with pytest.raises(BuildError, match="BuildKit-only"):
        _copy(engine, "a /b", flags={"link": ""})


def test_unknown_flag_rejected_not_ignored(engine):
    _write(engine, "a")
    with pytest.raises(BuildError, match=r"--exclude is not supported.*refusing to silently ignore"):
        _copy(engine, "a /b", flags={"exclude": "*.log"})


def test_add_parents_rejected(engine):
    _write(engine, "a")
    with pytest.raises(BuildError, match="--parents is not supported"):
        _copy(engine, "a /b", flags={"parents": ""}, name="ADD")


@pytest.mark.parametrize("flag", ["checksum", "keep-git-dir"])
def test_add_buildkit_flags_rejected_explicitly(engine, flag):
    _write(engine, "a")
    with pytest.raises(BuildError, match=f"--{flag} is not supported yet"):
        _copy(engine, "a /b", flags={flag: "v"}, name="ADD")


def test_plain_copy_still_works(engine):
    _write(engine, "hello.txt", "hi")
    _copy(engine, "hello.txt /greet.txt")
    assert _rootfs_has(engine, "greet.txt")


def test_parents_with_chown_numeric(engine):
    _write(engine, "src/a.py")
    with patch.object(copy_step, "resolve_chown", return_value=(100, 200)) as rc:
        _copy(engine, "src/a.py /app/", flags={"parents": "", "chown": "100:200"})
        rc.assert_called_once()
    assert _rootfs_has(engine, "app/src/a.py")
