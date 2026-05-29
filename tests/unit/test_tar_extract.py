import os
import tarfile
import tempfile

from chroot_distro.helpers.tar_extract import extract_tar_to_rootfs


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
        extract_tar_to_rootfs(tar_path, rootfs_dir, handle_whiteouts=True)

        # Assertions
        assert os.path.exists(os.path.join(rootfs_dir, "file2.txt"))
        assert not os.path.exists(os.path.join(rootfs_dir, "dir2", "temp_old.txt"))
        assert os.path.exists(os.path.join(rootfs_dir, "dir2", "temp.txt"))
        assert not os.path.exists(os.path.join(rootfs_dir, "dir1", "file1.txt"))
