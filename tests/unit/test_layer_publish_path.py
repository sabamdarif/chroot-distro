# Containment tests for where a build puts what it produces.
#
# A layer blob is named by the digest of its own bytes, so it is packed into the
# build's scratch directory and renamed into the layer cache afterwards. That
# rename used to be preceded by `os.makedirs(os.path.dirname(final))`, which
# accepts a symlink to a directory, and `os.replace()` then resolved the same
# name -- so a guest that left `cache/oci_layers -> <host dir>` behind (the cache
# is under the $PREFIX bound read-write into every non-isolated container)
# collected every layer a build produced. The build's own scratch root had the
# same shape one level up: `build-tmp` is a predictable name and mkdtemp()
# resolved it.

import errno
import os
import shutil
import stat

import pytest

from chroot_distro import atomic
from chroot_distro.atomic import publish_file
from chroot_distro.commands import build as build_cmd
from chroot_distro.commands.build import _make_build_tmp, _remove_build_tmp


@pytest.fixture
def outside(tmp_path):
    d = tmp_path / "outside"
    d.mkdir()
    (d / "keepsake").write_text("host content\n")
    return d


@pytest.fixture
def blob(tmp_path):
    src = tmp_path / "layer-0-0.tar.gz"
    src.write_bytes(b"layer bytes")
    return str(src)


@pytest.fixture
def layer_cache(tmp_path, monkeypatch):
    """A cache tree inside a state root, as it is in production."""
    root = tmp_path / "state"
    cache = root / "cache" / "oci_layers"
    cache.mkdir(parents=True)
    monkeypatch.setattr(atomic, "_STATE_ROOTS", (str(root),))
    return cache


# ── publishing a blob ─────────────────────────────────────────────────────────
def test_publish_lands_in_the_cache(blob, layer_cache):
    dest = layer_cache / "sha256_deadbeef"

    publish_file(blob, str(dest))

    assert dest.read_bytes() == b"layer bytes"
    assert not os.path.exists(blob)


def test_publish_refuses_a_symlinked_layer_cache(blob, layer_cache, outside):
    layer_cache.rmdir()
    os.symlink(str(outside), str(layer_cache))

    with pytest.raises(OSError) as excinfo:
        publish_file(blob, str(layer_cache / "sha256_deadbeef"))

    assert excinfo.value.errno == errno.ENOTDIR
    assert os.listdir(str(outside)) == ["keepsake"]
    # The blob is still where the build left it, not somewhere else.
    assert open(blob, "rb").read() == b"layer bytes"


def test_publish_replaces_a_planted_blob_name(blob, layer_cache, outside):
    # rename(2) follows no symlink at the destination name, so the link goes and
    # the host file it named is untouched.
    victim = outside / "keepsake"
    dest = layer_cache / "sha256_deadbeef"
    dest.symlink_to(victim)

    publish_file(blob, str(dest))

    assert victim.read_text() == "host content\n"
    assert not dest.is_symlink()
    assert dest.read_bytes() == b"layer bytes"


def test_publish_creates_missing_cache_levels(blob, layer_cache):
    shutil.rmtree(str(layer_cache))
    dest = layer_cache / "sha256_deadbeef"

    publish_file(blob, str(dest))

    assert dest.is_file()


def test_publish_leaves_a_user_destination_alone(blob, layer_cache, tmp_path, outside):
    # `build --output` names its own destination; a user pointing one through a
    # link of their own means it.
    os.symlink(str(outside), str(tmp_path / "chosen"))

    publish_file(blob, str(tmp_path / "chosen" / "image.tar"))

    assert (outside / "image.tar").read_bytes() == b"layer bytes"


# ── the build's scratch root ───────────────────────────────────────────────────
@pytest.fixture
def runtime(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    root.mkdir()
    monkeypatch.setattr(build_cmd, "RUNTIME_DIR", str(root))
    return root


def test_build_tmp_is_made_inside_the_runtime_tree(runtime):
    tmp_root, dir_fd, root_fd = _make_build_tmp()
    try:
        assert os.path.dirname(tmp_root) == str(runtime / "build-tmp")
        assert os.path.isdir(tmp_root)
        assert stat.S_IMODE(os.stat(tmp_root).st_mode) == 0o700
    finally:
        os.close(root_fd)
        _remove_build_tmp(tmp_root, dir_fd)
    assert not os.path.exists(tmp_root)


def test_the_root_descriptor_is_the_root_the_build_created(runtime, outside):
    # What every stage tree, the ADD spool and each COPY --from rootfs are made
    # off. Re-pointing the name afterwards must not move any of them, so the
    # descriptor has to be on the inode, not on the name.
    tmp_root, dir_fd, root_fd = _make_build_tmp()
    try:
        assert os.fstat(root_fd).st_ino == os.stat(tmp_root).st_ino
        os.rename(tmp_root, str(runtime / "moved"))
        os.symlink(str(outside), tmp_root)

        os.mkdir("stage-0", dir_fd=root_fd)

        assert os.path.isdir(str(runtime / "moved" / "stage-0"))
        assert os.listdir(str(outside)) == ["keepsake"]
    finally:
        os.close(root_fd)
        os.close(dir_fd)


def test_build_tmp_roots_are_distinct(runtime):
    first, first_fd, first_root_fd = _make_build_tmp()
    second, second_fd, second_root_fd = _make_build_tmp()
    try:
        assert first != second
    finally:
        os.close(first_root_fd)
        os.close(second_root_fd)
        _remove_build_tmp(first, first_fd)
        _remove_build_tmp(second, second_fd)


def test_build_tmp_does_not_follow_a_planted_name(runtime, outside, capsys):
    os.symlink(str(outside), str(runtime / "build-tmp"))

    tmp_root, dir_fd, root_fd = _make_build_tmp()
    try:
        # Refused, and the build falls back to the system temp directory the way
        # it always did when the runtime tree could not hold one.
        assert not tmp_root.startswith(str(runtime) + os.sep)
        assert os.listdir(str(outside)) == ["keepsake"]
        assert "falling back" in capsys.readouterr().err
    finally:
        os.close(root_fd)
        _remove_build_tmp(tmp_root, dir_fd)


def test_the_removal_does_not_follow_a_name_replaced_mid_build(runtime, outside):
    tmp_root, dir_fd, root_fd = _make_build_tmp()
    os.close(root_fd)
    (runtime / "build-tmp" / os.path.basename(tmp_root) / "stage-0").mkdir()
    # The window the descriptor closes: `build-tmp` is re-pointed while the build
    # runs, so a removal by name would empty the host directory instead.
    os.rename(str(runtime / "build-tmp"), str(runtime / "real"))
    os.symlink(str(outside), str(runtime / "build-tmp"))

    _remove_build_tmp(tmp_root, dir_fd)

    assert os.listdir(str(outside)) == ["keepsake"]
    assert os.listdir(str(runtime / "real")) == []


def test_the_removal_gets_out_a_sealed_directory(runtime):
    tmp_root, dir_fd, root_fd = _make_build_tmp()
    os.close(root_fd)
    sealed = os.path.join(tmp_root, "stage-0", "etc")
    os.makedirs(sealed)
    open(os.path.join(sealed, "passwd"), "w").close()
    os.chmod(os.path.dirname(sealed), 0o500)

    _remove_build_tmp(tmp_root, dir_fd)

    assert not os.path.exists(tmp_root)
