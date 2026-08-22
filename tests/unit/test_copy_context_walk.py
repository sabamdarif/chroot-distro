# A COPY/ADD source is located by one walk down the tree it belongs to -- the
# build context or the stage rootfs it came out of -- and every later step
# addresses it by the components that walk returned, opened O_NOFOLLOW off a
# descriptor on the tree. The names in a context are the Dockerfile author's and
# the names in a stage rootfs are the image's, so both are untrusted: a symlink
# leading out means "inside" here, as it does to a daemon that only ever sees the
# unpacked context.

import os
import time

import pytest

from chroot_distro import dirfd
from chroot_distro.helpers.build_engine import copy_step
from chroot_distro.helpers.build_engine.errors import BuildError


class _Engine:
    def __init__(self, base):
        self.build_dir = str(base / "ctx")
        self.ignore_patterns = []
        os.makedirs(self.build_dir, exist_ok=True)


@pytest.fixture
def engine(tmp_path):
    return _Engine(tmp_path)


@pytest.fixture
def outside(tmp_path):
    d = tmp_path / "outside"
    d.mkdir(mode=0o700)
    (d / "secret").write_bytes(b"host secret\n")
    return d


def _write(engine, rel, content="x"):
    path = os.path.join(engine.build_dir, rel)
    os.makedirs(os.path.dirname(path) or engine.build_dir, exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    return path


def _copy(engine, src, dest, *, is_dir_dest=True, file_map=None):
    file_map = {} if file_map is None else file_map
    copy_step._copy_from_context(
        engine, src, dest, is_dir_dest, file_map, 0, 0, None, auto_extract=False
    )
    return file_map


# ── where a source is looked for ──────────────────────────────────────────────
def test_a_file_entry_records_the_tree_and_the_components(engine):
    src = _write(engine, "app/main.py", "print(1)\n")
    file_map = _copy(engine, "app/main.py", "/opt/")

    entry = file_map["opt/main.py"]
    assert entry["kind"] == "file"
    assert entry["root"] == engine.build_dir
    assert entry["rel"] == ("app", "main.py")
    assert entry["size"] == os.stat(src).st_size


def test_a_symlinked_component_cannot_lead_the_source_out_of_the_context(engine, outside):
    os.symlink(str(outside), os.path.join(engine.build_dir, "escape"))

    with pytest.raises(BuildError, match="not found in build context"):
        _copy(engine, "escape/secret", "/opt/")


def test_a_clamped_component_resolves_inside_the_context(engine, outside):
    # The link re-anchors at the context root, so it means whatever the context
    # itself holds under that name -- here, a plant of its own.
    os.symlink("/inner", os.path.join(engine.build_dir, "escape"))
    _write(engine, "inner/secret", "context copy\n")

    file_map = _copy(engine, "escape/secret", "/opt/")

    entry = file_map["opt/secret"]
    assert entry["root"] == engine.build_dir
    assert entry["rel"] == ("inner", "secret")


def test_a_dotdot_in_the_spec_is_refused(engine):
    with pytest.raises(BuildError, match="escapes the build context"):
        _copy(engine, "../outside/secret", "/opt/")


def test_a_glob_match_only_reachable_outside_counts_for_nothing(engine, outside):
    os.symlink(str(outside), os.path.join(engine.build_dir, "escape"))

    with pytest.raises(BuildError, match="not found in build context"):
        _copy(engine, "escape/sec*", "/opt/")


def test_the_whole_context_can_be_copied(engine):
    _write(engine, "a.txt")
    _write(engine, "pkg/b.txt")

    file_map = _copy(engine, ".", "/app/")

    assert file_map["app/a.txt"]["kind"] == "file"
    assert file_map["app/pkg"]["kind"] == "dir"
    assert file_map["app/pkg/b.txt"]["rel"] == ("pkg", "b.txt")


def test_a_stage_source_is_confined_to_that_rootfs(tmp_path, outside):
    stage = tmp_path / "stage"
    stage.mkdir()
    os.symlink(str(outside), str(stage / "escape"))

    with pytest.raises(BuildError, match="not found in stage"):
        copy_step._copy_from_rootfs(str(stage), "/escape/secret", "/opt/", True, {}, 0, 0, None)


# ── the directory walk ────────────────────────────────────────────────────────
def test_a_symlinked_directory_is_recorded_as_a_symlink_with_its_own_mtime(engine):
    _write(engine, "tree/real/inside.txt")
    os.symlink("real", os.path.join(engine.build_dir, "tree", "link"))
    os.utime(
        os.path.join(engine.build_dir, "tree", "link"),
        (1234567890, 1234567890),
        follow_symlinks=False,
    )

    file_map = _copy(engine, "tree", "/app/")

    assert file_map["app/link"]["kind"] == "symlink"
    assert file_map["app/link"]["target"] == "real"
    assert file_map["app/link"]["mtime"] == 1234567890
    # Not descended: the link's target appears once, under its real name.
    assert "app/link/inside.txt" not in file_map
    assert file_map["app/real/inside.txt"]["kind"] == "file"


def test_a_symlinked_directory_is_put_through_dockerignore(engine):
    _write(engine, "tree/real/inside.txt")
    os.symlink("real", os.path.join(engine.build_dir, "tree", "link"))
    engine.ignore_patterns = ["tree/link"]

    file_map = _copy(engine, "tree", "/app/")

    assert "app/link" not in file_map
    assert "app/real/inside.txt" in file_map


def test_a_negated_pattern_inside_an_ignored_directory_still_arrives(engine):
    _write(engine, "tree/logs/a.log")
    _write(engine, "tree/logs/keep.txt")
    engine.ignore_patterns = ["tree/logs", "!tree/logs/keep.txt"]

    file_map = _copy(engine, "tree", "/app/")

    assert "app/logs/a.log" not in file_map
    assert file_map["app/logs/keep.txt"]["kind"] == "file"


def test_a_context_tree_deeper_than_the_descriptor_budget_is_walked(engine):
    depth = dirfd.MAX_OPEN_LEVELS + 8
    rel = "/".join(f"d{i}" for i in range(depth))
    _write(engine, f"{rel}/bottom.txt", "deep\n")

    file_map = _copy(engine, "d0", "/app/")

    arc = "app/" + "/".join(f"d{i}" for i in range(1, depth)) + "/bottom.txt"
    assert file_map[arc]["kind"] == "file"
    assert file_map[arc]["rel"][-1] == "bottom.txt"


def test_a_fifo_in_the_context_is_skipped(engine):
    _write(engine, "tree/real.txt")
    os.mkfifo(os.path.join(engine.build_dir, "tree", "pipe"))

    file_map = _copy(engine, "tree", "/app/")

    assert "app/pipe" not in file_map
    assert "app/real.txt" in file_map


def test_a_directory_mtime_is_not_recorded(engine):
    # Directory entries carry mtime 0 so a rebuild of the same tree hashes the
    # same, and the walk touching a directory cannot change a layer's digest.
    _write(engine, "tree/pkg/mod.py")
    os.utime(os.path.join(engine.build_dir, "tree", "pkg"), (time.time(), time.time()))

    file_map = _copy(engine, "tree", "/app/")

    assert file_map["app/pkg"]["mtime"] == 0
