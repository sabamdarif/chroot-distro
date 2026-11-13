import gzip
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

if sys.version_info >= (3, 14):
    import tarfile

    from compression import zstd
else:
    from backports import zstd
    from backports.zstd import tarfile
from unittest.mock import patch

import pytest

from chroot_distro.commands import backup
from chroot_distro.commands.backup import command_backup
from chroot_distro.commands.restore import command_restore
from chroot_distro.message import StdoutError
from chroot_distro.parser import build_parser


def _make_container(containers_dir, name):
    cont_dir = containers_dir / name
    rootfs_dir = cont_dir / "rootfs"
    rootfs_dir.mkdir(parents=True)
    (cont_dir / "manifest.json").write_text(json.dumps({"image": "alpine:latest"}))
    (rootfs_dir / "hello").write_text("hi")
    return cont_dir


_BACKUP_CLI = """
import sys
from contextlib import nullcontext
from chroot_distro import cli, paths
from chroot_distro.commands import backup

paths.CONTAINERS_DIR = sys.argv.pop(1)
cli._ensure_root_user = lambda: None
backup.ContainerLock = lambda *args, **kwargs: nullcontext()
backup.session.get_active_chroot_pids = lambda name: []
backup.mount_manager.get_active_mounts = lambda rootfs: []
cli.main()
"""


@pytest.fixture
def backup_cli(tmp_path):
    container = _make_container(tmp_path, "testcont")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    env.pop("PYTHONUNBUFFERED", None)

    def run(*args, unbuffered=False, **kwargs):
        flags = ["-u"] if unbuffered else []
        return subprocess.run(
            [sys.executable, *flags, "-c", _BACKUP_CLI, str(tmp_path), "backup", "testcont", *args],
            env=env,
            stderr=subprocess.PIPE,
            timeout=10,
            **kwargs,
        )

    return container, run


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX CLI signals and pipes")
@pytest.mark.parametrize("unbuffered", [False, True])
@pytest.mark.parametrize(("compression", "size"), [("gzip", 1), ("none", 32768)])
def test_backup_closed_stdout(backup_cli, compression, size, unbuffered):
    container, run = backup_cli
    (container / "rootfs" / "hello").write_bytes(b"x" * size)
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    with os.fdopen(write_fd, "wb") as output:
        result = run("-c", compression, unbuffered=unbuffered, stdout=output)

    assert result.returncode == 1, result.stderr
    assert b"Finished backing up" not in result.stderr
    assert b"Failed to backup file" not in result.stderr
    assert b"Failed to create backup archive" not in result.stderr
    assert b"Broken pipe" not in result.stderr
    assert b"Traceback" not in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX descriptors")
def test_backup_absent_stdout(backup_cli, tmp_path):
    _, run = backup_cli
    result = run(stdout=subprocess.PIPE, preexec_fn=lambda: os.close(1))
    assert result.returncode == 1, result.stderr
    assert result.stdout == result.stderr == b""

    archive = tmp_path / "backup.tar"
    result = run("-o", str(archive), stdout=subprocess.PIPE, preexec_fn=lambda: os.close(1))
    assert result.returncode == 0, result.stderr
    with tarfile.open(archive) as tf:
        assert tf.extractfile("testcont/rootfs/hello").read() == b"hi"


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX CLI signals")
def test_backup_stdout_gzip(backup_cli):
    _, run = backup_cli
    result = run("-c", "gzip", stdout=subprocess.PIPE)
    assert result.returncode == 0, result.stderr
    assert b"Finished backing up" in result.stderr
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(result.stdout))) as tf:
        assert tf.extractfile("testcont/rootfs/hello").read() == b"hi"


def test_archive_stdout_retries_only_unwritten_bytes_and_stops_after_epipe():
    writes = []

    def write(data):
        writes.append(bytes(data))
        if len(writes) == 1:
            return 3
        raise BrokenPipeError

    stream = SimpleNamespace(buffer=SimpleNamespace(write=write))
    writer = backup._ArchiveStdout(stream)
    for _ in range(2):
        with pytest.raises(StdoutError) as exc:
            writer.write(b"abcdef")
        assert exc.value.stream is stream
    assert writes == [b"abcdef", b"def"]


def test_backup_source_broken_pipe_is_a_source_failure(tmp_path, monkeypatch, capsys):
    container = _make_container(tmp_path, "testcont")
    source = container / "rootfs" / "hello"

    def open_source(*args, **kwargs):
        raise BrokenPipeError("source read failed")

    monkeypatch.setattr(backup, "open", open_source, raising=False)
    stdout = SimpleNamespace(buffer=io.BytesIO(), flush=lambda: None)
    with patch("sys.stdout", stdout), pytest.raises(SystemExit) as exc:
        backup._run_backup("testcont", str(source.parent), str(container / "missing"), None, "", False, stdout)
    assert exc.value.code == 1
    assert "Failed to backup file" in capsys.readouterr().err


@patch("chroot_distro.commands.backup.session.get_active_chroot_pids", return_value=[])
@patch("chroot_distro.commands.backup.mount_manager.get_active_mounts", return_value=[])
@patch("chroot_distro.commands.backup.ContainerLock")
@patch("chroot_distro.commands.restore.mount_manager.ensure_no_mounts")
@patch("chroot_distro.commands.restore.ContainerLock")
def test_backup_and_restore_end_to_end(
    mock_restore_lock,
    mock_ensure_no_mounts,
    mock_backup_lock,
    mock_get_active_mounts,
    mock_get_active_chroot_pids,
    tmp_path,
):
    # Setup paths inside tmp_path
    containers_dir = tmp_path / "containers"
    containers_dir.mkdir()

    # Define a container named "testcont"
    container_name = "testcont"
    cont_dir = containers_dir / container_name
    rootfs_dir = cont_dir / "rootfs"
    rootfs_dir.mkdir(parents=True)

    # 1. Create container files
    manifest_data = {"image": "alpine:latest", "architecture": "x86_64"}
    manifest_file = cont_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_data))

    # Add files/dirs in rootfs
    usr_bin = rootfs_dir / "usr" / "bin"
    usr_bin.mkdir(parents=True)

    test_file = usr_bin / "hello"
    test_file.write_text("echo hello")
    test_file.chmod(0o755)

    link_file = rootfs_dir / "bin_link"
    link_file.symlink_to("usr/bin/hello")

    # Backup destination
    backup_archive = tmp_path / "testcont_backup.tar.xz"

    # Build backup arguments
    parser = build_parser()
    backup_args = parser.parse_args(["backup", container_name, "--output", str(backup_archive)])

    # Patch paths to point to our temp containers directory
    with (
        patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)),
        patch("chroot_distro.commands.restore.CONTAINERS_DIR", str(containers_dir)),
    ):
        # 2. Run backup
        command_backup(backup_args)

        assert backup_archive.exists()

        # Verify the tar file has valid structure: <container_name>/manifest.json and <container_name>/rootfs/...
        with tarfile.open(backup_archive, "r:xz") as tf:
            names = tf.getnames()
            assert f"{container_name}/manifest.json" in names
            assert f"{container_name}/rootfs/usr/bin/hello" in names
            assert f"{container_name}/rootfs/bin_link" in names

            # Numeric ownership is preserved (a non-root image must survive a
            # round-trip); only the owner/group names are dropped.
            info = tf.getmember(f"{container_name}/rootfs/usr/bin/hello")
            assert info.uid == os.getuid()
            assert info.gid == os.getgid()
            assert info.uname == ""
            assert info.gname == ""

        # 3. Simulate restoration to a new container named "restoredcont"
        # We can rename the archive file or restore directly.
        # But wait, restore command determines target container name from the top-level folder name inside the archive.
        # So it will restore to "testcont" again.
        # Let's delete "testcont" first.
        import shutil

        shutil.rmtree(cont_dir)
        assert not cont_dir.exists()

        # Build restore arguments
        restore_args = parser.parse_args(["restore", str(backup_archive)])

        # Run restore
        command_restore(restore_args)

        # 4. Verify restoration
        assert cont_dir.exists()
        assert manifest_file.exists()
        assert json.loads(manifest_file.read_text()) == manifest_data

        assert test_file.exists()
        assert test_file.read_text() == "echo hello"

        # Check permissions were restored (mode is preserved, masked by 0o7777)
        assert (test_file.stat().st_mode & 0o777) == 0o755

        # Check symlink was restored
        assert link_file.is_symlink()
        assert os.readlink(link_file) == "usr/bin/hello"


@patch("chroot_distro.commands.backup.session.get_active_chroot_pids", return_value=[])
@patch("chroot_distro.commands.backup.mount_manager.get_active_mounts", return_value=[])
@patch("chroot_distro.commands.backup.ContainerLock")
@patch("chroot_distro.commands.restore.mount_manager.ensure_no_mounts")
@patch("chroot_distro.commands.restore.ContainerLock")
def test_backup_and_restore_zstd(
    mock_restore_lock,
    mock_ensure_no_mounts,
    mock_backup_lock,
    mock_get_active_mounts,
    mock_get_active_chroot_pids,
    tmp_path,
):
    containers_dir = tmp_path / "containers_zst"
    containers_dir.mkdir()

    container_name = "testcontzst"
    cont_dir = containers_dir / container_name
    rootfs_dir = cont_dir / "rootfs"
    rootfs_dir.mkdir(parents=True)

    manifest_data = {"image": "alpine:latest", "architecture": "x86_64"}
    manifest_file = cont_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_data))

    usr_bin = rootfs_dir / "usr" / "bin"
    usr_bin.mkdir(parents=True)

    test_file = usr_bin / "hello"
    test_file.write_text("echo hello")
    test_file.chmod(0o755)

    link_file = rootfs_dir / "bin_link"
    link_file.symlink_to("usr/bin/hello")

    backup_archive = tmp_path / "testcont_backup.tar.zst"

    parser = build_parser()
    backup_args = parser.parse_args(["backup", container_name, "--output", str(backup_archive)])

    with (
        patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)),
        patch("chroot_distro.commands.restore.CONTAINERS_DIR", str(containers_dir)),
    ):
        command_backup(backup_args)

        assert backup_archive.exists()

        with zstd.ZstdFile(backup_archive, "rb") as zs, tarfile.open(fileobj=zs, mode="r:") as tf:
            names = tf.getnames()
            assert f"{container_name}/manifest.json" in names
            assert f"{container_name}/rootfs/usr/bin/hello" in names
            assert f"{container_name}/rootfs/bin_link" in names

        import shutil

        shutil.rmtree(cont_dir)
        assert not cont_dir.exists()

        restore_args = parser.parse_args(["restore", str(backup_archive)])
        command_restore(restore_args)

        assert cont_dir.exists()
        assert manifest_file.exists()
        assert json.loads(manifest_file.read_text()) == manifest_data
        assert test_file.exists()
        assert test_file.read_text() == "echo hello"
        assert (test_file.stat().st_mode & 0o777) == 0o755
        assert link_file.is_symlink()
        assert os.readlink(link_file) == "usr/bin/hello"


@patch("chroot_distro.commands.backup.session.get_active_chroot_pids", return_value=[])
@patch("chroot_distro.commands.backup.mount_manager.get_active_mounts", return_value=[])
@patch("chroot_distro.commands.backup.ContainerLock")
def test_backup_failure_returns_exit_code_1(
    mock_backup_lock,
    mock_get_active_mounts,
    mock_get_active_chroot_pids,
    tmp_path,
    capsys,
):
    containers_dir = tmp_path / "containers"
    containers_dir.mkdir()
    _make_container(containers_dir, "testcont")
    backup_archive = tmp_path / "testcont.tar.xz"
    parser = build_parser()
    backup_args = parser.parse_args(["backup", "testcont", "--output", str(backup_archive)])

    with (
        patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)),
        patch("chroot_distro.commands.backup._add_path", return_value=False),
        pytest.raises(SystemExit) as exc,
    ):
        command_backup(backup_args)

    assert exc.value.code == 1
    assert "could not be archived" in capsys.readouterr().err
    assert not backup_archive.exists()


@patch("chroot_distro.commands.backup.session.get_active_chroot_pids", return_value=[])
@patch("chroot_distro.commands.backup.mount_manager.get_active_mounts", return_value=[])
@patch("chroot_distro.commands.backup.ContainerLock")
@patch("chroot_distro.commands.restore.mount_manager.ensure_no_mounts")
@patch("chroot_distro.commands.restore.ContainerLock")
def test_restore_failure_returns_exit_code_1(
    mock_restore_lock,
    mock_ensure_no_mounts,
    mock_backup_lock,
    mock_get_active_mounts,
    mock_get_active_chroot_pids,
    tmp_path,
    monkeypatch,
    capsys,
):
    containers_dir = tmp_path / "containers"
    containers_dir.mkdir()
    _make_container(containers_dir, "testcont")
    backup_archive = tmp_path / "testcont.tar.xz"
    parser = build_parser()
    backup_args = parser.parse_args(["backup", "testcont", "--output", str(backup_archive)])

    with patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)):
        command_backup(backup_args)

    assert backup_archive.exists()

    import shutil

    shutil.rmtree(containers_dir / "testcont")
    assert not (containers_dir / "testcont").exists()

    original_open = open

    def _deny_restore_write(path, *args, **kwargs):
        mode = kwargs.get("mode") or (args[0] if args else None)
        if mode == "wb" and "testcont" in str(path) and "rootfs" in str(path):
            raise OSError(13, "Permission denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _deny_restore_write)

    restore_args = parser.parse_args(["restore", str(backup_archive)])
    with (
        patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)),
        patch("chroot_distro.commands.restore.CONTAINERS_DIR", str(containers_dir)),
        pytest.raises(SystemExit) as exc,
    ):
        command_restore(restore_args)

    assert exc.value.code == 1
    assert "could not be restored" in capsys.readouterr().err
