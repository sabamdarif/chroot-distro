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


@pytest.mark.parametrize("name", ["", ".", "..", "/escape", "a/b", "a\0b"])
def test_descriptor_write_rejects_nonleaf_destinations(state_root, name):
    fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError), atomic.atomic_write(name, dir_fd=fd):
            pytest.fail("invalid destination accepted")
        os.fstat(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("binary", [False, True])
def test_descriptor_write_retains_parent_and_file_mode(state_root, binary):
    fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with atomic.atomic_write("result", dir_fd=fd, mode=0o640, binary_mode=binary) as fh:
            fh.write(b"content" if binary else "content")
        os.fstat(fd)
    finally:
        os.close(fd)
    assert (state_root / "result").read_bytes() == b"content"
    assert stat.S_IMODE((state_root / "result").stat().st_mode) == 0o640


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("timing", ["before", "during"])
def test_descriptor_publication_detects_staging_substitution(state_root, tmp_path, monkeypatch, kind, timing):
    victim = tmp_path / "outside"
    victim.write_text("KEEP")
    victim.chmod(0o600)
    real_replace = os.replace

    def substitute(tmp):
        tmp.unlink()
        if kind == "symlink":
            tmp.symlink_to(victim)
        else:
            os.link(victim, tmp)

    def replace(src, dst, **kwargs):
        if timing == "during":
            substitute(state_root / src)
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as exc:
            with atomic.atomic_write("manifest.json", dir_fd=fd, mode=0o644) as fh:
                fh.write("{}")
                if timing == "before":
                    staging, = state_root.iterdir()
                    substitute(staging)
        assert exc.value.errno == errno.ESTALE
        os.fstat(fd)
    finally:
        os.close(fd)
    assert victim.read_text() == "KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600


def test_descriptor_write_follows_original_parent_after_rename(state_root, tmp_path):
    fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
    original = tmp_path / "moved"
    try:
        with atomic.atomic_write("manifest.json", dir_fd=fd) as fh:
            state_root.rename(original)
            state_root.mkdir()
            fh.write("{}")
    finally:
        os.close(fd)
    assert (original / "manifest.json").read_text() == "{}"
    assert list(state_root.iterdir()) == []


@pytest.mark.parametrize("descriptor", [False, True])
@pytest.mark.parametrize("entry", ["absent", "file", "symlink", "hardlink", "racing"])
def test_no_replace_preserves_existing_entries(tmp_path, descriptor, entry):
    parent = tmp_path / "parent"
    parent.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("KEEP")
    dest = parent / "result"
    if entry == "file":
        dest.write_text("KEEP")
    elif entry == "symlink":
        dest.symlink_to(victim)
    elif entry == "hardlink":
        dest.hardlink_to(victim)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY) if descriptor else None
    try:
        def publish():
            with atomic.atomic_write("result" if descriptor else str(dest), dir_fd=fd, replace=False, mode=0o640) as fh:
                fh.write("new")
                if entry == "racing":
                    dest.write_text("KEEP")

        if entry == "absent":
            publish()
            assert dest.read_text() == "new"
            assert stat.S_IMODE(dest.stat().st_mode) == 0o640
            assert dest.stat().st_nlink == 1
        else:
            with pytest.raises(FileExistsError):
                publish()
            assert dest.read_text() == "KEEP"
        if fd is not None:
            os.fstat(fd)
    finally:
        if fd is not None:
            os.close(fd)
    assert victim.read_text() == "KEEP"
    assert [p.name for p in parent.iterdir()] == ["result"]


@pytest.mark.parametrize("descriptor", [False, True])
def test_no_replace_interrupt_leaves_no_file(tmp_path, descriptor):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY) if descriptor else None
    try:
        with pytest.raises(KeyboardInterrupt):
            with atomic.atomic_write("result" if descriptor else str(tmp_path / "result"), dir_fd=fd, replace=False) as fh:
                fh.write("partial")
                raise KeyboardInterrupt
    finally:
        if fd is not None:
            os.close(fd)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("timing", ["before", "during"])
def test_no_replace_detects_substituted_staging_inode(tmp_path, monkeypatch, timing):
    real_link = os.link
    parent = tmp_path / "parent"
    parent.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("KEEP")
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)

    def substitute(src):
        path = parent / src
        path.unlink()
        real_link(victim, path)

    def link(src, dst, **kwargs):
        if timing == "during":
            substitute(src)
        real_link(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", link)
    try:
        with pytest.raises(OSError) as exc:
            with atomic.atomic_write("result", dir_fd=fd, replace=False, mode=0o644) as fh:
                fh.write("new")
                if timing == "before":
                    staging, = parent.iterdir()
                    substitute(staging.name)
        assert exc.value.errno == errno.ESTALE
    finally:
        os.close(fd)
    assert victim.read_text() == "KEEP"
