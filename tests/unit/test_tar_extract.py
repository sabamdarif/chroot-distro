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
    """Write *members* — (TarInfo, bytes|None) pairs — into a plain tar."""
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
    the tree before the member is written — exactly what a process sharing the
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
