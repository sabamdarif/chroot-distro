# Containment tests for the stage rootfs a build works against.
#
# The build kept `<scratch>/stage-N/rootfs` as a *path* and resolved it again for
# every snapshot, every layer packed, every COPY/ADD and every RUN. The scratch
# root is 0700, but that is only the invoking user's own permission, and a
# process a previous RUN step left running *is* the invoking user: nothing kills
# one off Termux, and on Termux the whole runtime tree is bound read-write into
# every non-isolated container -- which a cross-arch step guarantees by binding
# $TERMUX_PREFIX for the emulator's loader. Moving the rootfs aside and leaving a
# symlink under the name was therefore enough to make the rest of the build read
# and write somewhere else entirely, and what it reads goes into the layer `push`
# uploads.
#
# Every test here does the same thing: hold the descriptor the engine would hold,
# re-point the name, and check the work still lands on the inode.

import io
import os
import sys
from types import SimpleNamespace

import pytest

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro.helpers import layer_diff
from chroot_distro.helpers.build_engine import copy_step, handlers, run_step
from chroot_distro.helpers.build_engine.stage import Stage
from chroot_distro.helpers.build_engine.users import resolve_user_for_chroot


@pytest.fixture
def staged(tmp_path):
    """A stage directory, its rootfs, and a decoy the name can be aimed at."""
    stage_dir = tmp_path / "stage-0"
    rootfs = stage_dir / "rootfs"
    rootfs.mkdir(parents=True)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "HOST-SECRET").write_bytes(b"host content\n")

    stage = Stage(
        index=0,
        name="",
        rootfs_dir=str(rootfs),
        target_arch_pd="x86_64",
        dir_fd=os.open(str(stage_dir), os.O_RDONLY | os.O_DIRECTORY),
        rootfs_fd=os.open(str(rootfs), os.O_RDONLY | os.O_DIRECTORY),
    )
    try:
        yield stage, rootfs, decoy
    finally:
        stage.close()


def _repoint(path, decoy):
    """Swap *path*'s name for a symlink to the decoy, as a step could."""
    moved = str(path) + ".moved"
    os.rename(str(path), moved)
    os.symlink(str(decoy), str(path))
    return moved


# ── the snapshots that straddle a RUN step ────────────────────────────────────
def test_snapshot_reads_the_pinned_inode(staged):
    stage, rootfs, decoy = staged
    (rootfs / "real").write_bytes(b"x")
    _repoint(rootfs, decoy)

    snap = layer_diff.snapshot(stage.rootfs_dir, rootfs_fd=stage.rootfs_fd)

    assert "real" in snap
    assert "HOST-SECRET" not in snap


def test_snapshot_without_a_pin_still_follows_the_name(staged):
    # The other half of the assertion above: the name really does lead somewhere
    # else by then, so the pin is what makes the difference.
    stage, rootfs, decoy = staged
    (rootfs / "real").write_bytes(b"x")
    _repoint(rootfs, decoy)

    assert "HOST-SECRET" in layer_diff.snapshot(stage.rootfs_dir)


# ── the layer the step produces ───────────────────────────────────────────────
def test_layer_packs_the_pinned_inode(staged, tmp_path):
    stage, rootfs, decoy = staged
    (rootfs / "real").write_bytes(b"image content\n")
    _repoint(rootfs, decoy)

    out = tmp_path / "layer.tar.gz"
    layer_diff.write_layer_tar(
        stage.rootfs_dir,
        ["real", "HOST-SECRET"],
        [],
        str(out),
        rootfs_fd=stage.rootfs_fd,
    )

    with tarfile.open(str(out), "r:gz") as tf:
        names = tf.getnames()
    assert "real" in names
    assert "HOST-SECRET" not in names


# ── COPY/ADD's destination ────────────────────────────────────────────────────
def test_materialise_writes_into_the_pinned_inode(staged, tmp_path):
    stage, rootfs, decoy = staged
    payload = tmp_path / "payload"
    payload.write_bytes(b"copied\n")
    entry = {
        "kind": "file",
        "root": str(payload.parent),
        "rel": (payload.name,),
        "src": str(payload),
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "mtime": 0,
        "size": payload.stat().st_size,
    }
    moved = _repoint(rootfs, decoy)

    copy_step._materialise_files(stage.rootfs_dir, {"opt/app": entry}, rootfs_fd=stage.rootfs_fd)

    with open(os.path.join(moved, "opt", "app"), "rb") as fh:
        assert fh.read() == b"copied\n"
    assert not os.path.exists(str(decoy / "opt"))


# ── COPY --from=<stage>, where the stage rootfs is the *source* ───────────────
def test_copy_from_a_pinned_stage_reads_the_pinned_inode(staged):
    stage, rootfs, decoy = staged
    (rootfs / "app").mkdir()
    (rootfs / "app" / "bin").write_bytes(b"image content\n")
    _repoint(rootfs, decoy)

    file_map: dict[str, object] = {}
    copy_step._copy_from_rootfs(
        stage.rootfs_dir,
        "/app",
        "/out",
        True,
        file_map,
        0,
        0,
        None,
        from_rootfs_fd=stage.rootfs_fd,
    )

    with layer_diff.MapSources() as sources:
        fd, _st = sources.open(file_map["out/bin"])
        try:
            assert os.read(fd, 64) == b"image content\n"
        finally:
            os.close(fd)


# ── WORKDIR ───────────────────────────────────────────────────────────────────
def test_workdir_creates_inside_the_pinned_inode(staged, tmp_path, monkeypatch):
    stage, rootfs, decoy = staged
    layers = tmp_path / "layers"
    layers.mkdir()
    monkeypatch.setattr(handlers, "layer_cache_path", lambda digest: str(layers / digest.replace(":", "_")))
    moved = _repoint(rootfs, decoy)
    engine = SimpleNamespace(current=stage, tmp_root=str(tmp_path))

    handlers.do_workdir(
        engine,
        {"name": "WORKDIR", "value": "/srv/app", "exec_form": False, "flags": {}, "heredocs": [], "lineno": 1},
    )

    assert os.path.isdir(os.path.join(moved, "srv", "app"))
    assert not os.path.exists(str(decoy / "srv"))


# ── USER, which decides the uid the step runs as ──────────────────────────────
def test_user_is_resolved_out_of_the_pinned_inode(staged):
    stage, rootfs, decoy = staged
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "passwd").write_text("app:x:1234:1234::/home/app:/bin/sh\n")
    (decoy / "etc").mkdir()
    (decoy / "etc" / "passwd").write_text("app:x:0:0::/root:/bin/sh\n")
    _repoint(rootfs, decoy)

    assert resolve_user_for_chroot(stage.rootfs_dir, "app", root_fd=stage.rootfs_fd) == (1234, 1234)


# ── the newroot chroot(2) is handed ───────────────────────────────────────────
def test_run_pins_the_step_to_the_stage_descriptor(staged, tmp_path, monkeypatch):
    # chroot(2) resolving its own argument is the last name-based read of the
    # rootfs a step makes, and it happens after every check here has finished,
    # so the step is handed the stage rather than a path to walk again.
    stage, _rootfs, _decoy = staged
    seen: dict[str, object] = {}

    def fake_run_plain(rootfs, config, child_env, stdin_input, engine=None, stage=None, mounts=None):
        seen.update(rootfs=rootfs, config=config, stage=stage)
        return 0

    monkeypatch.setattr(run_step, "_run_plain", fake_run_plain)

    engine = SimpleNamespace(quiet=True, verbose=False, isolation_mode="none", tmp_root=str(tmp_path))
    assert run_step._exec_chroot(engine, stage, ["true"], None) == 0

    assert seen["stage"] is stage
    assert seen["config"].command == ["true"]


def test_the_step_child_starts_on_the_pinned_inode(staged, monkeypatch):
    # What makes chroot(2)'s "." mean the pinned inode: the child fchdirs onto
    # the descriptor first. With the chroot itself stubbed out the cwd is
    # observable, so the step's own command reports it.
    stage, rootfs, decoy = staged
    moved = _repoint(rootfs, decoy)
    monkeypatch.setattr(run_step, "enter_chroot", lambda _newroot, **_kw: None)

    config = SimpleNamespace(
        rootfs=stage.rootfs_dir,
        command=["/bin/sh", "-c", "pwd > pinned.txt"],
        uid=None,
        gid=None,
        groups=None,
        workdir="/",
    )
    pid = run_step._fork_step(config, {"PATH": "/usr/bin:/bin"}, rootfs_fd=stage.rootfs_fd)
    assert run_step._wait_for_child(pid) == 0

    with open(os.path.join(moved, "pinned.txt")) as fh:
        assert fh.read().strip() == moved
    assert not os.path.exists(os.path.join(str(decoy), "pinned.txt"))


# ── the scratch root every stage tree is made under ───────────────────────────
@pytest.fixture
def scratch(tmp_path):
    """The build's scratch root, its descriptor, and a decoy for its name."""
    root = tmp_path / "scratch"
    root.mkdir()
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, fd, decoy
    finally:
        os.close(fd)


def test_stage_dirs_are_made_off_the_scratch_descriptor(scratch):
    from chroot_distro.helpers.build_engine.engine import BuildEngine

    root, fd, decoy = scratch
    engine = BuildEngine.__new__(BuildEngine)
    engine.tmp_root = str(root)
    engine.tmp_root_fd = fd
    moved = _repoint(root, decoy)

    stage_fd, rootfs_fd = engine._make_stage_dirs(0)
    assert stage_fd is not None and rootfs_fd is not None
    os.close(stage_fd)
    os.close(rootfs_fd)

    assert os.path.isdir(os.path.join(moved, "stage-0", "rootfs"))
    assert os.listdir(str(decoy)) == []


def test_a_copy_from_image_is_pulled_into_the_scratch_descriptor(scratch, monkeypatch):
    # The tree an image this build has no say over is unpacked into, so the pull
    # is handed the descriptor and never the name.
    root, fd, decoy = scratch
    monkeypatch.setattr(
        copy_step,
        "pull_image",
        lambda _ref, rootfs_fd, _arch: open(
            os.open("pulled", os.O_CREAT | os.O_WRONLY, dir_fd=rootfs_fd), "wb"
        ).close(),
    )
    engine = SimpleNamespace(tmp_root=str(root), tmp_root_fd=fd, quiet=True, target_arch_pd="x86_64")
    moved = _repoint(root, decoy)

    path, pulled_fd = copy_step._pull_throwaway_image(engine, "alpine:latest")
    try:
        assert os.fstat(pulled_fd).st_ino == os.stat(os.path.join(moved, os.path.basename(path))).st_ino
        assert "pulled" in os.listdir(os.path.join(moved, os.path.basename(path)))
    finally:
        os.close(pulled_fd)
    assert os.listdir(str(decoy)) == []


# ── the spool ADD stages content it did not find as a file in ─────────────────
def test_the_add_spool_writes_and_reads_through_its_descriptor(scratch):
    # A URL body and each member of an auto-extracted archive are written here
    # and read twice more: once into the rootfs, once into the layer `push`
    # uploads. Only the create resolves a name.
    root, fd, decoy = scratch
    engine = SimpleNamespace(tmp_root=str(root), tmp_root_fd=fd)
    spool = copy_step._Spool(*copy_step._open_scratch_dir(engine, "add-spool"))
    moved = _repoint(root, decoy)
    try:
        name, written = spool.stream(io.BytesIO(b"spooled\n"))
        assert written == len(b"spooled\n")
        file_map: dict[str, object] = {}
        copy_step._spool_entry(file_map, "opt/blob", spool, name, 0o644, 0, 0, 0)

        assert os.path.isfile(os.path.join(moved, "add-spool", name))
        assert os.listdir(str(decoy)) == []

        with layer_diff.MapSources() as sources:
            src_fd, st = sources.open(file_map["opt/blob"])
            try:
                assert os.read(src_fd, 64) == b"spooled\n"
                assert st.st_size == len(b"spooled\n")
            finally:
                os.close(src_fd)
    finally:
        spool.close()
