# Where an atomic write actually lands.
#
# Every cache, manifest, layer and state-file writer publishes through
# `atomic_replace`/`atomic_write`, and both used to reach the destination
# directory by name twice -- makedirs(exist_ok=True), which is happy with a
# symlink to a directory, and mkstemp(dir=...), which resolves it again. On
# Termux RUNTIME_DIR and BASE_CACHE_DIR sit under the $PREFIX bound read-write
# into every non-isolated container, so a guest can leave a link under any
# directory name in either tree and have the bytes written on the far side of
# it. Below those two roots the components are walked with O_NOFOLLOW; a path
# the *user* named keeps the plain behaviour.

import errno
import os
import stat

import pytest

from chroot_distro import atomic


@pytest.fixture
def state_root(tmp_path, monkeypatch):
    """Make tmp_path/state the one state root, as the real ones are on Termux."""
    root = tmp_path / "state"
    root.mkdir()
    monkeypatch.setattr(atomic, "_STATE_ROOTS", (str(root),))
    return root


def _outside(tmp_path):
    out = tmp_path / "outside"
    out.mkdir()
    return out


# ── the walk ──────────────────────────────────────────────────────────────────
def test_a_symlinked_directory_component_is_refused(state_root, tmp_path):
    outside = _outside(tmp_path)
    os.symlink(str(outside), str(state_root / "cache"))

    with pytest.raises(OSError) as excinfo:
        with atomic.atomic_write(str(state_root / "cache" / "blob")) as fh:
            fh.write("x")

    assert excinfo.value.errno == errno.ENOTDIR
    assert os.listdir(str(outside)) == []


def test_a_deep_symlinked_component_is_refused(state_root, tmp_path):
    # The reported shape: `cache/oci_layers -> <host dir>`, one level down.
    outside = _outside(tmp_path)
    (state_root / "cache").mkdir()
    os.symlink(str(outside), str(state_root / "cache" / "oci_layers"))

    with pytest.raises(OSError):
        with atomic.atomic_replace(str(state_root / "cache" / "oci_layers" / "sha256_ab")) as tmp:
            with open(tmp, "w") as fh:
                fh.write("x")

    assert os.listdir(str(outside)) == []


def test_missing_directories_are_still_created(state_root):
    dest = state_root / "containers" / "box" / "manifest.json"

    with atomic.atomic_write(str(dest)) as fh:
        fh.write("{}")

    assert dest.read_text() == "{}"


def test_a_symlink_planted_as_the_destination_is_replaced(state_root, tmp_path):
    # rename(2) follows no symlink at the destination name, so the link goes and
    # what it pointed at is untouched -- the parents were always the hole.
    outside = _outside(tmp_path)
    victim = outside / "victim"
    victim.write_text("KEEP")
    dest = state_root / "sentinel"
    dest.symlink_to(victim)

    with atomic.atomic_write(str(dest)) as fh:
        fh.write("new")

    assert not dest.is_symlink()
    assert dest.read_text() == "new"
    assert victim.read_text() == "KEEP"


def test_the_temporary_goes_when_the_block_raises(state_root):
    with pytest.raises(RuntimeError):
        with atomic.atomic_write(str(state_root / "half")) as fh:
            fh.write("half")
            raise RuntimeError("interrupted")

    assert os.listdir(str(state_root)) == []


def test_mode_is_applied_before_the_rename(state_root):
    dest = state_root / "keyfile"

    with atomic.atomic_write(str(dest), mode=0o640) as fh:
        fh.write("x")

    assert stat.S_IMODE(dest.stat().st_mode) == 0o640


def test_a_hardlink_under_the_temp_name_is_not_written_through(state_root, monkeypatch, tmp_path):
    # O_NOFOLLOW cannot tell a hardlink from an ordinary file; O_EXCL is what
    # keeps the write off an inode the caller did not create. The temp name is
    # unpredictable in production, so it is pinned here to plant one at all.
    outside = _outside(tmp_path)
    victim = outside / "victim"
    victim.write_text("KEEP")
    monkeypatch.setattr(atomic.dirfd, "temp_name", lambda name, suffix: "pinned.tmp")
    os.link(str(victim), str(state_root / "pinned.tmp"))

    with atomic.atomic_write(str(state_root / "sentinel")) as fh:
        fh.write("new")

    assert victim.read_text() == "KEEP"
    assert (state_root / "sentinel").read_text() == "new"


# ── a path the user chose ─────────────────────────────────────────────────────
def test_a_path_outside_the_state_tree_keeps_the_plain_behaviour(state_root, tmp_path):
    # `backup -o` and `build --output` name their own destination, and a user
    # who points one through a symlinked directory of their own means it.
    outside = _outside(tmp_path)
    os.symlink(str(outside), str(tmp_path / "chosen"))

    with atomic.atomic_write(str(tmp_path / "chosen" / "backup.tar")) as fh:
        fh.write("archive")

    assert (outside / "backup.tar").read_text() == "archive"


def test_the_state_root_itself_is_not_a_destination(state_root, tmp_path):
    # A path *equal* to a root has no components to walk; it is treated as the
    # user's own rather than mistaken for a file inside the tree.
    root, parts = atomic._state_location(str(state_root))

    assert (root, parts) == (None, ())
