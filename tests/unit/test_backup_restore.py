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

from chroot_distro import locking, paths
from chroot_distro.commands import backup, restore
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


def test_restore_refuses_a_planted_lock_before_creating_the_container(tmp_path, monkeypatch, capsys):
    locks = tmp_path / "locks"
    locks.mkdir()
    monkeypatch.setattr(locking, "RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(locking, "LOCKS_DIR", str(locks))
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(tmp_path / "containers"))
    victim = tmp_path / "victim"
    victim.write_text("KEEP")
    (locks / "box.lock").symlink_to(victim)

    archive = tmp_path / "backup.tar"
    with tarfile.open(archive, "w") as tf:
        entry = tarfile.TarInfo("box/rootfs")
        entry.type = tarfile.DIRTYPE
        tf.addfile(entry)

    with pytest.raises(SystemExit) as exc:
        command_restore(SimpleNamespace(archive=str(archive)))
    assert exc.value.code == 1
    assert "unexpected entry" in capsys.readouterr().err
    assert victim.read_text() == "KEEP"
    assert not (tmp_path / "containers" / "box").exists()


_BACKUP_CLI = """
import sys
from contextlib import nullcontext
from chroot_distro import cli, paths
from chroot_distro.commands import backup, restore

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


@pytest.mark.skipif(os.name != "posix", reason="Requires POSIX filenames")
def test_backup_escapes_displayed_paths_and_preserves_tar_names(backup_cli, tmp_path):
    container, run = backup_cli
    name = "bad\\file\x1b[2J\x9b\u202e\nnext"
    escaped = rb"bad\\file\e[2J\x9b\u202e\nnext"
    (container / "rootfs" / name).write_bytes(b"payload")
    archive = tmp_path / f"{name}.tar"

    result = run("-v", "-o", str(archive), stdout=subprocess.PIPE)
    assert result.returncode == 0, result.stderr
    assert not result.stdout
    assert escaped + b".tar'" in result.stderr
    assert b"Adding: 'testcont/rootfs/" + escaped + b"'" in result.stderr
    assert all(control not in result.stderr for control in (b"\x1b[2J", b"\xc2\x9b", b"\xe2\x80\xae", b"\nnext"))
    with tarfile.open(archive) as tf:
        assert tf.extractfile(f"testcont/rootfs/{name}").read() == b"payload"


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
    source = container / "rootfs" / "demo\nfile"
    (source.parent / "hello").rename(source)

    def open_source(*args, **kwargs):
        raise BrokenPipeError("source read failed\x1b[2J")

    monkeypatch.setattr(backup, "open", open_source, raising=False)
    stdout = SimpleNamespace(buffer=io.BytesIO(), flush=lambda: None)
    with patch("sys.stdout", stdout), pytest.raises(SystemExit) as exc:
        backup._run_backup("testcont", str(source.parent), str(container / "missing"), None, "", False, stdout)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"Failed to backup file {source.parent}/demo\\nfile: source read failed\\e[2J" in err
    assert "\x1b[2J" not in err


@patch("chroot_distro.commands.backup.session.get_active_chroot_pids", return_value=[])
@patch("chroot_distro.commands.backup.mount_manager.get_active_mounts", return_value=[])
@patch("chroot_distro.commands.backup.ContainerLock")
@patch("chroot_distro.commands.restore.ContainerLock")
def test_backup_and_restore_end_to_end(
    mock_restore_lock,
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
    with patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)):
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
@patch("chroot_distro.commands.restore.ContainerLock")
def test_backup_and_restore_zstd(
    mock_restore_lock,
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

    with patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)):
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
@patch("chroot_distro.commands.restore.ContainerLock")
def test_restore_failure_returns_exit_code_1(
    mock_restore_lock,
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

    def deny_restore_write(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(restore.dirfd, "open_new_at", deny_restore_write)

    restore_args = parser.parse_args(["restore", str(backup_archive)])
    with (
        patch("chroot_distro.paths.CONTAINERS_DIR", str(containers_dir)),
        pytest.raises(SystemExit) as exc,
    ):
        command_restore(restore_args)

    assert exc.value.code == 1
    assert "Failed to restore container: Permission denied" in capsys.readouterr().err
    assert (containers_dir / "testcont/.install-incomplete").is_file()


def test_restore_recovers_leading_dot_before_absolute_path(tmp_path, capsys):
    archive = tmp_path / "valid.tar"
    archive.write_text("data")
    with pytest.raises(SystemExit) as exc:
        command_restore(SimpleNamespace(archive=f"./{archive}", verbose=False))
    assert exc.value.code == 1
    assert "Failed to restore container" in capsys.readouterr().err


@pytest.fixture
def restore_store(tmp_path, monkeypatch):
    store = tmp_path / "containers"
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(store))
    monkeypatch.setattr(locking, "RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(locking, "LOCKS_DIR", str(tmp_path / "locks"))
    return store


def _add_restore_entry(tf, name, data=b"", *, kind=tarfile.REGTYPE, link="", mode=0o644):
    member = tarfile.TarInfo(name)
    member.type = kind
    member.uid, member.gid = os.geteuid(), os.getegid()
    member.size = len(data)
    member.mode = mode
    member.linkname = link
    tf.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize("sidecar", ["file", "absent", "symlink"])
def test_backup_restore_round_trip_for_installed_rootfs(restore_store, tmp_path, monkeypatch, sidecar):
    name = "installed-rootfs"
    source_store = tmp_path / "source"
    source = _make_container(source_store, name)
    source_manifest = source / "manifest.json"
    manifest_data = source_manifest.read_bytes()
    if sidecar == "absent":
        source_manifest.unlink()
    elif sidecar == "symlink":
        source_manifest.rename(source / "metadata")
        source_manifest.symlink_to("metadata")
    os.link(source / "rootfs/hello", source / "rootfs/hello-copy")

    archive = tmp_path / "backup.tar.gz"
    parser = build_parser()
    with monkeypatch.context() as scoped:
        scoped.setattr(paths, "CONTAINERS_DIR", str(source_store))
        scoped.setattr(backup.session, "get_active_chroot_pids", lambda name: [])
        scoped.setattr(backup.mount_manager, "get_active_mounts", lambda rootfs: [])
        command_backup(parser.parse_args(["backup", name, "-o", str(archive)]))

    with tarfile.open(archive) as tf:
        assert tf.getmember(f"{name}/rootfs/hello-copy").islnk()

    if sidecar == "absent":
        with archive.open("rb") as stream, monkeypatch.context() as scoped:
            scoped.setattr(sys, "stdin", SimpleNamespace(buffer=stream, isatty=lambda: False))
            command_restore(parser.parse_args(["restore"]))
    else:
        command_restore(parser.parse_args(["restore", str(archive)]))

    restored = restore_store / name
    assert sorted(path.name for path in restore_store.iterdir()) == [name]
    assert paths.container_is_installed(name)
    assert (restored / "rootfs/hello").read_text() == "hi"
    assert (restored / "rootfs/hello-copy").read_text() == "hi"
    if sidecar == "file":
        assert (restored / "manifest.json").read_bytes() == manifest_data
    else:
        assert not os.path.lexists(restored / "manifest.json")


@pytest.mark.parametrize("name", ["box", "manifest.json", "rootfs"])
def test_restore_legacy_layout(restore_store, tmp_path, name):
    archive = tmp_path / "old.tar"
    prefix = f"installed-rootfs/{name}"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "installed-rootfs", kind=tarfile.DIRTYPE)
        _add_restore_entry(tf, prefix, kind=tarfile.DIRTYPE, mode=0o755)
        _add_restore_entry(tf, f"{prefix}/hello", b"legacy")

    flags = ["--legacy-layout"] if name == "rootfs" else []
    command_restore(build_parser().parse_args(["restore", *flags, str(archive)]))

    assert sorted(path.name for path in restore_store.iterdir()) == [name]
    assert paths.container_is_installed(name)
    assert (restore_store / name / "rootfs/hello").read_bytes() == b"legacy"


def test_restore_legacy_override_refuses_current_manifest_before_lock(restore_store, tmp_path, monkeypatch, capsys):
    archive = tmp_path / "backup.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "installed-rootfs/manifest.json", b"{}")
        _add_restore_entry(tf, "installed-rootfs/rootfs", kind=tarfile.DIRTYPE)

    monkeypatch.setattr(restore, "ContainerLock", lambda *a, **kw: pytest.fail("unexpected lock"))
    with pytest.raises(SystemExit, match="1"):
        command_restore(build_parser().parse_args(["restore", "--legacy-layout", str(archive)]))

    assert "Omit --legacy-layout" in capsys.readouterr().err
    assert not restore_store.exists()


@pytest.mark.parametrize(
    ("name", "first", "second"),
    [
        ("installed-rootfs", "installed-rootfs/rootfs", "installed-rootfs/manifest.json"),
        ("box", "installed-rootfs/box", "box/rootfs"),
    ],
)
def test_restore_refuses_mixed_layouts(restore_store, tmp_path, name, first, second):
    archive = tmp_path / "mixed.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, first, kind=tarfile.DIRTYPE, mode=0o755)
        _add_restore_entry(tf, second, kind=tarfile.DIRTYPE, mode=0o755)

    with pytest.raises(SystemExit, match="1"):
        command_restore(build_parser().parse_args(["restore", str(archive)]))

    assert sorted(path.name for path in restore_store.iterdir()) == [name]
    assert paths.is_install_incomplete(name)
    assert paths.installed_containers() == []


@pytest.mark.parametrize("failure", ["hardlink", "truncated", "interrupt", "manifest", "ownership", "directory mode"])
def test_failed_restore_is_incomplete_and_can_be_retried(restore_store, tmp_path, monkeypatch, capsys, failure):
    archive = tmp_path / "broken.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "box/rootfs/kept", b"first")
        if failure == "hardlink":
            _add_restore_entry(tf, "box/rootfs/broken", kind=tarfile.LNKTYPE, link="box/rootfs/missing")
        elif failure == "truncated":
            _add_restore_entry(tf, "box/rootfs/broken", b"x" * 40000)
        elif failure == "manifest":
            _add_restore_entry(tf, "box/manifest.json", b'{"image_ref":"old"}')
        elif failure == "directory mode":
            _add_restore_entry(tf, "box/rootfs/restricted", kind=tarfile.DIRTYPE, mode=0o500)
        else:
            _add_restore_entry(tf, "box/rootfs/broken", b"second")

    if failure == "truncated":
        with archive.open("r+b") as stream:
            stream.truncate(4096)

    def fail(*args, **kwargs):
        raise OSError("injected restore failure")

    with monkeypatch.context() as scoped:
        if failure == "interrupt":
            def interrupt(*args, **kwargs):
                raise KeyboardInterrupt

            scoped.setattr(restore, "draw_bytes_bar", interrupt)
        elif failure == "manifest":
            scoped.setattr(restore, "atomic_write", fail)
        elif failure == "ownership":
            scoped.setattr(os, "fchown", fail)
        elif failure == "directory mode":
            chmod = os.fchmod

            def fail_final_mode(fd, mode):
                if mode == 0o500:
                    fail()
                chmod(fd, mode)

            scoped.setattr(os, "fchmod", fail_final_mode)
        with pytest.raises(SystemExit, match="1"):
            command_restore(SimpleNamespace(archive=str(archive)))

    box = restore_store / "box"
    assert (box / "rootfs").is_dir()
    assert paths.is_install_incomplete("box")
    assert not paths.container_is_installed("box")
    assert paths.installed_containers() == []
    assert "Finished restoring" not in capsys.readouterr().err

    (box / "manifest.json").write_text('{"image_ref":"stale"}')
    (box / "rootfs").chmod(0o500)
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "installed-rootfs/box/good", b"restored")
        _add_restore_entry(tf, "installed-rootfs/box/copy", kind=tarfile.LNKTYPE, link="installed-rootfs/box/good")
    command_restore(SimpleNamespace(archive=str(archive)))

    original, copied = box / "rootfs/good", box / "rootfs/copy"
    assert paths.container_is_installed("box")
    assert not paths.is_install_incomplete("box")
    assert not (box / "manifest.json").exists()
    assert sorted(p.name for p in original.parent.iterdir()) == ["copy", "good"]
    assert original.read_bytes() == copied.read_bytes() == b"restored"
    assert original.stat().st_ino != copied.stat().st_ino
    assert original.parent.stat().st_mode & 0o777 == 0o755


def test_restore_preserves_rootfs_that_appears_during_creation(restore_store, tmp_path, monkeypatch, capsys):
    archive = tmp_path / "backup.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "box/rootfs/new", b"new")

    mkdir = os.mkdir
    rootfs = restore_store / "box/rootfs"

    def competing_mkdir(path, *args, **kwargs):
        if path == "rootfs" and kwargs.get("dir_fd") is not None:
            mkdir(rootfs)
            (rootfs / "existing").write_text("keep")
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", competing_mkdir)
    for _ in range(2):
        with pytest.raises(SystemExit, match="1"):
            command_restore(SimpleNamespace(archive=str(archive)))
        assert paths.container_is_installed("box")
        assert sorted(entry.name for entry in rootfs.iterdir()) == ["existing"]
    assert "already installed" in capsys.readouterr().err


@pytest.mark.parametrize("mount_location", ["rootfs", "rootfs/child", None])
def test_restore_refuses_retry_if_mounts_cannot_be_ruled_out(
    restore_store, tmp_path, monkeypatch, capsys, mount_location
):
    from chroot_distro.helpers import mount_manager

    box = _make_container(restore_store, "box")
    (box / ".install-incomplete").touch()

    def open_mounts(path):
        assert path == "/proc/self/mounts"
        if mount_location is None:
            raise FileNotFoundError("mount table unavailable")
        return io.StringIO(f"tmpfs {box / mount_location} tmpfs rw 0 0\n")

    monkeypatch.setattr(mount_manager, "open", open_mounts, raising=False)
    archive = tmp_path / "backup.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "box/rootfs/new", b"new")
    with pytest.raises(SystemExit, match="1"):
        command_restore(SimpleNamespace(archive=str(archive)))
    assert (box / "rootfs/hello").read_text() == "hi"
    assert paths.is_install_incomplete("box")
    assert not (box / "rootfs/new").exists()
    expected = "mount table unavailable" if mount_location is None else "Active mounts"
    assert expected in capsys.readouterr().err


@pytest.mark.parametrize("component", ["container", "parent"])
def test_restore_confines_writes_after_storage_replacement(restore_store, tmp_path, monkeypatch, component):
    archive = tmp_path / "backup.tar"
    with tarfile.open(archive, "w") as tf:
        _add_restore_entry(tf, "box/rootfs/dir/first", b"first")
        _add_restore_entry(tf, "box/rootfs/dir/keep", b"changed")

    box = restore_store / "box"
    source = box if component == "container" else box / "rootfs/dir"
    saved = tmp_path / "saved"
    outside = tmp_path / "outside"
    destination = outside / "rootfs/dir" if component == "container" else outside
    destination.mkdir(parents=True)
    (destination / "keep").write_text("keep")

    def replace_after_first_entry(*args, **kwargs):
        if not saved.exists():
            source.rename(saved)
            source.symlink_to(outside, target_is_directory=True)

    if component == "container":
        monkeypatch.setattr(restore, "draw_bytes_bar", replace_after_first_entry)
    else:
        descend_at = restore.dirfd.descend_at

        def replace_before_walk(fd, parts, **kwargs):
            if list(parts) == ["dir"] and source.is_dir():
                replace_after_first_entry()
            return descend_at(fd, parts, **kwargs)

        monkeypatch.setattr(restore.dirfd, "descend_at", replace_before_walk)

    with pytest.raises(SystemExit, match="1"):
        command_restore(SimpleNamespace(archive=str(archive)))
    assert ((saved if component == "container" else box) / ".install-incomplete").is_file()
    assert (destination / "keep").read_text() == "keep"


def test_restore_marker_blocks_backup_diff_rename_and_reset(restore_store, tmp_path):
    from chroot_distro.commands import diff, rename, reset
    from chroot_distro.exceptions import ContainerNotFoundError

    box = _make_container(restore_store, "box")
    (box / ".install-incomplete").touch()
    output = tmp_path / "partial.tar"
    args = SimpleNamespace(container_name="box", orig_name="box", new_name="other", output=str(output))

    for command in (command_backup, rename.command_rename, reset.command_reset):
        with pytest.raises(SystemExit, match="1"):
            command(args)
    with pytest.raises(ContainerNotFoundError, match="not installed"):
        diff.command_diff(args)
    assert not output.exists()
    assert not (restore_store / "other").exists()
    assert (box / "rootfs/hello").read_text() == "hi"
