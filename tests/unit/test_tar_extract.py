import gzip
import os
import shutil
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import contextlib
import io
import tempfile
from unittest.mock import patch

import pytest

from chroot_distro.helpers import tar_extract
from chroot_distro.helpers.docker.layers import apply_layer
from chroot_distro.helpers.tar_extract import extract_tar_to_rootfs


@contextlib.contextmanager
def _rootfs_fd(rootfs_dir):
    """The extractor takes the rootfs as a descriptor; open one for a test."""
    fd = os.open(rootfs_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


def _tar_with(tar_path, members):
    """Write *members*, which are (TarInfo, bytes|None) pairs, into a plain tar."""
    with tarfile.open(tar_path, "w") as tar:
        for member, payload in members:
            if payload is None:
                tar.addfile(member)
            else:
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))


def test_extract_tar_to_rootfs():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a test tar file
        tar_path = os.path.join(tmp_dir, "test.tar")
        rootfs_dir = os.path.join(tmp_dir, "rootfs")
        os.makedirs(rootfs_dir)

        # We will create file structure inside a temp directory first, then tar it
        src_dir = os.path.join(tmp_dir, "src")
        os.makedirs(src_dir)

        # We want to test that:
        # 1. file2.txt is extracted normally
        # 2. dir2/.wh..wh..opq deletes old files in dir2, but new files in the tar (if any) are kept
        # 3. dir1/.wh.file1.txt deletes file1.txt

        os.makedirs(os.path.join(src_dir, "dir1"))
        os.makedirs(os.path.join(src_dir, "dir2"))

        with open(os.path.join(src_dir, "file2.txt"), "w") as f:
            f.write("world")

        # Opaque whiteout file in dir2
        with open(os.path.join(src_dir, "dir2", ".wh..wh..opq"), "w") as f:
            f.write("")
        with open(os.path.join(src_dir, "dir2", "temp.txt"), "w") as f:
            f.write("new_temp")

        # Sibling whiteout in dir1 (deletes file1.txt)
        with open(os.path.join(src_dir, "dir1", ".wh.file1.txt"), "w") as f:
            f.write("")

        # Write to tar
        with tarfile.open(tar_path, "w") as tar:
            tar.add(src_dir, arcname=".")

        # Pre-create rootfs items to test whiteouts
        # dir2/temp_old.txt should be deleted by the opaque whiteout
        os.makedirs(os.path.join(rootfs_dir, "dir2"))
        with open(os.path.join(rootfs_dir, "dir2", "temp_old.txt"), "w") as f:
            f.write("will_be_deleted")

        # dir1/file1.txt should be deleted by .wh.file1.txt sibling whiteout
        os.makedirs(os.path.join(rootfs_dir, "dir1"))
        with open(os.path.join(rootfs_dir, "dir1", "file1.txt"), "w") as f:
            f.write("will_be_deleted")

        # Extract
        with _rootfs_fd(rootfs_dir) as fd:
            extract_tar_to_rootfs(tar_path, fd, handle_whiteouts=True)

        # Assertions
        assert os.path.exists(os.path.join(rootfs_dir, "file2.txt"))
        assert not os.path.exists(os.path.join(rootfs_dir, "dir2", "temp_old.txt"))
        assert os.path.exists(os.path.join(rootfs_dir, "dir2", "temp.txt"))
        assert not os.path.exists(os.path.join(rootfs_dir, "dir1", "file1.txt"))


@patch("os.fchown")
@patch("os.chown")
def test_extract_tar_preserves_ownership(mock_chown, mock_fchown, tmp_path):
    """Each member's uid/gid still goes on, now through its descriptor.

    A regular file is chown'ed on the fd it was written through (before the
    fchmod, since chown(2) drops setuid/setgid), and a directory by name off
    its parent's descriptor with follow_symlinks=False.
    """
    tar_path = str(tmp_path / "test.tar")
    rootfs_dir = tmp_path / "rootfs"
    rootfs_dir.mkdir()

    directory = tarfile.TarInfo("dir")
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    directory.uid, directory.gid = 1007, 1008
    regular = tarfile.TarInfo("dir/file.txt")
    regular.mode = 0o644
    regular.uid, regular.gid = 1005, 1006
    _tar_with(tar_path, [(directory, None), (regular, b"hello")])

    with _rootfs_fd(str(rootfs_dir)) as fd:
        extract_tar_to_rootfs(tar_path, fd)

    assert any(call.args[1:] == (1005, 1006) for call in mock_fchown.call_args_list)
    assert any(call.args[1:] == (1007, 1008) for call in mock_chown.call_args_list)
    assert (rootfs_dir / "dir" / "file.txt").read_text() == "hello"


def test_extract_tar_zst_to_rootfs():
    if sys.version_info >= (3, 14):
        from compression import zstd
    else:
        from backports import zstd

    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "test.tar.zst")
        rootfs_dir = os.path.join(tmp_dir, "rootfs")
        os.makedirs(rootfs_dir)

        src_dir = os.path.join(tmp_dir, "src")
        os.makedirs(src_dir)

        with open(os.path.join(src_dir, "file.txt"), "w") as f:
            f.write("zstd works")

        with zstd.ZstdFile(tar_path, "w") as zs, tarfile.open(fileobj=zs, mode="w") as tar:
            tar.add(src_dir, arcname=".")

        with _rootfs_fd(rootfs_dir) as fd:
            extract_tar_to_rootfs(tar_path, fd)

        assert os.path.exists(os.path.join(rootfs_dir, "file.txt"))
        with open(os.path.join(rootfs_dir, "file.txt")) as f:
            assert f.read() == "zstd works"


def test_parent_repointed_after_the_resolve_is_refused(tmp_path):
    """The write follows the descriptor the parent was walked to, not its name.

    The resolve says `etc` and the directory is swapped for a symlink out of
    the tree before the member is written, exactly what a process sharing the
    prefix can do on Termux. Re-walking the answer with O_NOFOLLOW refuses it,
    where os.makedirs()/open(dest) followed the link and wrote outside.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    rootfs_dir = tmp_path / "rootfs"
    (rootfs_dir / "etc").mkdir(parents=True)
    tar_path = str(tmp_path / "swap.tar")
    member = tarfile.TarInfo("etc/passwd")
    member.mode = 0o644
    _tar_with(tar_path, [(member, b"root:x:0:0:::\n")])

    real = tar_extract.safe_resolve_parts_at

    def _swapping(root_fd, parts):
        answer = real(root_fd, parts)
        if answer == ["etc"]:
            shutil.rmtree(rootfs_dir / "etc")
            os.symlink(str(outside), rootfs_dir / "etc")
        return answer

    with (
        patch.object(tar_extract, "safe_resolve_parts_at", _swapping),
        _rootfs_fd(str(rootfs_dir)) as fd,
        pytest.raises(OSError),
    ):
        extract_tar_to_rootfs(tar_path, fd)

    assert list(outside.iterdir()) == []


def test_regular_member_never_written_through_a_hardlink(tmp_path):
    """A hardlink standing under a member's name gets a fresh inode instead.

    O_NOFOLLOW cannot tell a hardlink from an ordinary file, so the only thing
    that keeps the member's bytes off the inode it shares is creating the
    destination with O_EXCL (dirfd.open_new_at).
    """
    rootfs_dir = tmp_path / "rootfs"
    rootfs_dir.mkdir()
    kept = rootfs_dir / "kept"
    kept.write_text("host content")
    os.link(kept, rootfs_dir / "planted")

    tar_path = str(tmp_path / "link.tar")
    member = tarfile.TarInfo("planted")
    member.mode = 0o644
    _tar_with(tar_path, [(member, b"member content")])

    with _rootfs_fd(str(rootfs_dir)) as fd:
        extract_tar_to_rootfs(tar_path, fd)

    assert (rootfs_dir / "planted").read_text() == "member content"
    assert kept.read_text() == "host content"


def test_member_with_a_trailing_dot_is_dropped(tmp_path):
    """`target/.` names the directory itself, so the member is not written.

    Acted on, a symlink member of that shape emptied the directory before
    failing on EEXIST; a regular one ended the extraction on EISDIR.
    """
    rootfs_dir = tmp_path / "rootfs"
    (rootfs_dir / "target").mkdir(parents=True)
    (rootfs_dir / "target" / "keep").write_text("x")

    tar_path = str(tmp_path / "dot.tar")
    member = tarfile.TarInfo("target/.")
    member.type = tarfile.SYMTYPE
    member.linkname = "/etc"
    _tar_with(tar_path, [(member, None)])

    with _rootfs_fd(str(rootfs_dir)) as fd:
        extract_tar_to_rootfs(tar_path, fd)

    assert (rootfs_dir / "target").is_dir()
    assert not (rootfs_dir / "target").is_symlink()
    assert (rootfs_dir / "target" / "keep").read_text() == "x"


def test_hardlink_member_copies_content_with_its_ownership(tmp_path):
    """A deferred hardlink is materialised as a copy, off both descriptors."""
    rootfs_dir = tmp_path / "rootfs"
    rootfs_dir.mkdir()

    tar_path = str(tmp_path / "hard.tar")
    source = tarfile.TarInfo("source.txt")
    source.mode = 0o644
    link = tarfile.TarInfo("copy.txt")
    link.type = tarfile.LNKTYPE
    link.linkname = "source.txt"
    _tar_with(tar_path, [(source, b"shared"), (link, None)])

    with _rootfs_fd(str(rootfs_dir)) as fd:
        extract_tar_to_rootfs(tar_path, fd)

    assert (rootfs_dir / "copy.txt").read_text() == "shared"


def test_hardlink_member_cannot_escape_the_rootfs(tmp_path):
    """A linkname climbing out is dropped, not resolved against the host."""
    secret = tmp_path / "secret"
    secret.write_text("host secret")
    rootfs_dir = tmp_path / "rootfs"
    rootfs_dir.mkdir()

    tar_path = str(tmp_path / "escape.tar")
    link = tarfile.TarInfo("stolen.txt")
    link.type = tarfile.LNKTYPE
    link.linkname = "../secret"
    _tar_with(tar_path, [(link, None)])

    with _rootfs_fd(str(rootfs_dir)) as fd:
        extract_tar_to_rootfs(tar_path, fd)

    assert not (rootfs_dir / "stolen.txt").exists()


@pytest.mark.parametrize("opaque", [False, True])
@pytest.mark.parametrize("marker_first", [False, True])
def test_whiteout_applies_only_to_lower_layer(tmp_path, opaque, marker_first):
    rootfs = tmp_path / "rootfs"
    (rootfs / "dir").mkdir(parents=True)
    (rootfs / "dir" / "new").write_bytes(b"lower")
    (rootfs / "dir" / "old").write_bytes(b"old")
    marker = ".wh..wh..opq" if opaque else ".wh.new"
    members = [(tarfile.TarInfo(f"dir/{marker}"), b""), (tarfile.TarInfo("dir/new"), b"upper")]
    layer = tmp_path / "layer.tar"
    _tar_with(layer, members if marker_first else reversed(members))

    with _rootfs_fd(rootfs) as fd:
        apply_layer(str(layer), fd)

    assert (rootfs / "dir" / "new").read_bytes() == b"upper"
    assert (rootfs / "dir" / "old").exists() is not opaque
    assert not (rootfs / "dir" / marker).exists()


def test_whiteout_leaves_former_target_of_replaced_directory_symlink(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "real").mkdir(parents=True)
    (rootfs / "real" / "keep").write_bytes(b"lower")
    (rootfs / "alias").symlink_to("real")
    layer = tmp_path / "layer.tar"
    directory = tarfile.TarInfo("alias")
    directory.type = tarfile.DIRTYPE
    _tar_with(layer, [(tarfile.TarInfo("alias/.wh..wh..opq"), b""), (directory, None)])

    with _rootfs_fd(rootfs) as fd:
        apply_layer(str(layer), fd)

    assert (rootfs / "real" / "keep").read_bytes() == b"lower"
    assert not (rootfs / "alias").is_symlink()
    assert not list((rootfs / "alias").iterdir())


@pytest.mark.parametrize("case", ["boundary", "payload", "one-zero", "gzip-trailer", "gzip-crc"])
def test_incomplete_layer_fails_before_applying_changes(tmp_path, case):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "old").write_bytes(b"lower")
    layer = tmp_path / "layer.tar"
    _tar_with(layer, [(tarfile.TarInfo(".wh.old"), b""), (tarfile.TarInfo("new"), b"payload")])
    complete = layer.read_bytes()
    if case == "gzip-trailer":
        damaged = gzip.compress(complete)[:-8]
    elif case == "gzip-crc":
        encoded = gzip.compress(complete)
        damaged = encoded[:-8] + bytes([encoded[-8] ^ 1]) + encoded[-7:]
    else:
        end = {"boundary": 1536, "payload": 1027, "one-zero": 2048}[case]
        damaged = complete[:end]
    layer.write_bytes(damaged)

    with _rootfs_fd(rootfs) as fd, pytest.raises(OSError, match="Invalid image layer tar"):
        apply_layer(str(layer), fd)

    assert (rootfs / "old").read_bytes() == b"lower"
    assert not (rootfs / "new").exists()


def _hardlink(name, target):
    link = tarfile.TarInfo(name)
    link.type = tarfile.LNKTYPE
    link.linkname = target
    return link


def test_layer_replaces_file_types_and_resolves_forward_hardlinks(tmp_path, monkeypatch):
    rootfs = tmp_path / "rootfs"
    (rootfs / "to-file").mkdir(parents=True)
    (rootfs / "to-file" / "old").touch()
    (rootfs / "to-dir").write_bytes(b"old")
    (rootfs / "keep").write_bytes(b"unchanged")
    (rootfs / "second").symlink_to("keep")
    (rootfs / "first").mkdir()
    (rootfs / "first" / "old").touch()
    layer = tmp_path / "layer.tar"
    directory = tarfile.TarInfo("to-dir")
    directory.type = tarfile.DIRTYPE
    first = _hardlink("first", "second")
    first.uid, first.gid = 4001, 4002
    _tar_with(layer, [(first, None), (_hardlink("second", "source"), None),
                      (tarfile.TarInfo("source"), b"upper"), (directory, None),
                      (tarfile.TarInfo("to-dir/new"), b"child"), (tarfile.TarInfo("to-file"), b"file")])
    ownership = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: ownership.append((os.fstat(fd).st_ino, uid, gid)))

    with _rootfs_fd(rootfs) as fd:
        apply_layer(str(layer), fd)

    assert (rootfs / "to-file").read_bytes() == b"file"
    assert (rootfs / "to-dir" / "new").read_bytes() == b"child"
    assert (rootfs / "first").read_bytes() == (rootfs / "second").read_bytes() == b"upper"
    assert not (rootfs / "second").is_symlink()
    assert (rootfs / "keep").read_bytes() == b"unchanged"
    assert ((rootfs / "first").stat().st_ino, 4001, 4002) in ownership


@pytest.mark.parametrize("target,error", [("missing", "missing tar hardlink source"), ("first", "cyclic tar hardlink")])
def test_layer_rejects_unresolved_hardlinks(tmp_path, target, error):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    layer = tmp_path / "layer.tar"
    _tar_with(layer, [(_hardlink("first", "second"), None), (_hardlink("second", target), None)])

    with _rootfs_fd(rootfs) as fd, pytest.raises(OSError, match=error):
        apply_layer(str(layer), fd)
    assert not list(rootfs.iterdir())


def test_later_members_supersede_pending_links_and_directory_times(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    layer = tmp_path / "layer.tar"
    first = tarfile.TarInfo("dir")
    first.type, first.mtime = tarfile.DIRTYPE, 1
    second = tarfile.TarInfo("dir")
    second.type, second.mtime = tarfile.DIRTYPE, 2
    third = tarfile.TarInfo("dir")
    third.type, third.mtime = tarfile.DIRTYPE, 3
    _tar_with(layer, [
        (first, None), (_hardlink("dir/old-link", "missing"), None),
        (tarfile.TarInfo("dir"), b"file"), (second, None), (third, None),
        (_hardlink("old-link", "missing"), None), (tarfile.TarInfo("old-link"), b"new"),
    ])

    with _rootfs_fd(rootfs) as fd:
        apply_layer(str(layer), fd)
    assert not list((rootfs / "dir").iterdir())
    assert (rootfs / "dir").stat().st_mtime == 3
    assert (rootfs / "old-link").read_bytes() == b"new"
