# What identifies the build context to the cache. COPY and ADD keep no cache
# entry of their own: they always pack, and the layer they pack is named by the
# digest of its own content, which is what the next step's recipe hash chains
# onto. So a change to a file the instruction copies invalidates every step that
# follows it, a change to a file `.dockerignore` excludes does not, and editing
# `.dockerignore` itself moves whichever files it now covers.

import itertools
import os

import pytest

from chroot_distro.helpers.build_engine import copy_step
from chroot_distro.helpers.build_engine.dockerignore import load_dockerignore
from chroot_distro.helpers.layer_diff import write_files_layer

_seq = itertools.count()


class _Engine:
    def __init__(self, base):
        self.build_dir = str(base / "ctx")
        self.ignore_patterns = []
        os.makedirs(self.build_dir, exist_ok=True)


@pytest.fixture
def engine(tmp_path):
    return _Engine(tmp_path)


def _write(engine, rel, content):
    path = os.path.join(engine.build_dir, rel)
    os.makedirs(os.path.dirname(path) or engine.build_dir, exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


def _reload_patterns(engine):
    engine.ignore_patterns = load_dockerignore(engine.build_dir)


def _copy_digest(engine, tmp_path, src=".", dest="/app/"):
    """The layer digest one `COPY <src> <dest>` of this context produces."""
    file_map = {}
    copy_step._copy_from_context(engine, src, dest, True, file_map, 0, 0, None, auto_extract=False)
    out = tmp_path / f"layer-{next(_seq)}.tar.gz"
    digest, _size, _diff_id = write_files_layer(file_map, str(out))
    return digest


def test_the_same_context_packs_to_the_same_layer(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")

    assert _copy_digest(engine, tmp_path) == _copy_digest(engine, tmp_path)


def test_an_included_file_changes_the_layer_every_later_step_chains_onto(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    before = _copy_digest(engine, tmp_path)

    _write(engine, "app/main.py", "print(2)\n")

    assert _copy_digest(engine, tmp_path) != before


def test_a_new_file_changes_the_layer(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    before = _copy_digest(engine, tmp_path)

    _write(engine, "app/extra.py", "\n")

    assert _copy_digest(engine, tmp_path) != before


def test_an_excluded_file_does_not(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    _write(engine, ".dockerignore", "*.log\nbuild\n")
    _reload_patterns(engine)
    before = _copy_digest(engine, tmp_path)

    # `*.log` covers the context root only, which is Docker's rule, so the
    # excluded pair is one top-level log and one file under an excluded folder.
    _write(engine, "debug.log", "noise\n")
    _write(engine, "build/out.o", "object\n")

    assert _copy_digest(engine, tmp_path) == before


def test_an_excluded_directory_is_not_in_the_layer(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    _write(engine, "build/out.o", "object\n")
    _write(engine, ".dockerignore", "build\n")
    _reload_patterns(engine)

    file_map = {}
    copy_step._copy_from_context(engine, ".", "/app/", True, file_map, 0, 0, None, auto_extract=False)

    assert "app/build" not in file_map
    assert "app/build/out.o" not in file_map
    assert "app/app/main.py" in file_map


def test_a_re_included_child_brings_its_excluded_directory_back(engine, tmp_path):
    _write(engine, "build/out.o", "object\n")
    _write(engine, "build/keep.txt", "keep\n")
    _write(engine, ".dockerignore", "build\n!build/keep.txt\n")
    _reload_patterns(engine)

    file_map = {}
    copy_step._copy_from_context(engine, ".", "/app/", True, file_map, 0, 0, None, auto_extract=False)

    assert "app/build/out.o" not in file_map
    assert file_map["app/build/keep.txt"]["kind"] == "file"


def test_editing_the_ignore_file_moves_the_files_it_covers(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    _write(engine, "app/debug.log", "noise\n")
    _write(engine, ".dockerignore", "*.log\n")
    _reload_patterns(engine)
    ignored = _copy_digest(engine, tmp_path)

    _write(engine, ".dockerignore", "!nothing\n")
    _reload_patterns(engine)

    assert _copy_digest(engine, tmp_path) != ignored


def test_the_ignore_file_itself_is_always_copied(engine, tmp_path):
    _write(engine, "app/main.py", "print(1)\n")
    _write(engine, ".dockerignore", "*\n")
    _reload_patterns(engine)

    file_map = {}
    copy_step._copy_from_context(engine, ".", "/app/", True, file_map, 0, 0, None, auto_extract=False)

    assert "app/.dockerignore" in file_map
    assert "app/app/main.py" not in file_map
