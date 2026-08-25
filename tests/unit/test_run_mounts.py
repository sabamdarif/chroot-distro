import os
from unittest.mock import patch

import pytest

from chroot_distro import dirfd
from chroot_distro.helpers.build_engine import run_mounts
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.run_mounts import (
    run_mount_session,
    validate_and_parse_run_flags,
)


def _instr(flags, lineno=7):
    return {"name": "RUN", "flags": flags, "lineno": lineno}


# ── flag validation ───────────────────────────────────────────────────────────
def test_no_flags_returns_empty():
    assert validate_and_parse_run_flags(_instr({})) == []


def test_unknown_run_flag_rejected():
    with pytest.raises(BuildError, match=r"--frobnicate.*line 7"):
        validate_and_parse_run_flags(_instr({"frobnicate": "x"}))


def test_network_none_rejected_explicitly():
    with pytest.raises(BuildError, match="network-namespace"):
        validate_and_parse_run_flags(_instr({"network": "none"}))


@pytest.mark.parametrize("value", ["host", "default"])
def test_network_host_default_accepted_noop(value):
    assert validate_and_parse_run_flags(_instr({"network": value})) == []


def test_network_garbage_rejected():
    with pytest.raises(BuildError, match="--network=bogus"):
        validate_and_parse_run_flags(_instr({"network": "bogus"}))


@pytest.mark.parametrize("value", ["insecure", "sandbox"])
def test_security_rejected(value):
    with pytest.raises(BuildError, match="sequenced after"):
        validate_and_parse_run_flags(_instr({"security": value}))


# ── mount parsing ─────────────────────────────────────────────────────────────
def test_default_type_is_bind_and_readonly():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "target=/x,source=sub"}))
    assert m.type == "bind"
    assert m.target == "/x"
    assert m.source == "sub"
    assert m.readonly is True


def test_aliases_dst_src_ro():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=bind,dst=/x,src=s,ro=false"}))
    assert m.target == "/x"
    assert m.source == "s"
    assert m.readonly is False


def test_rw_alias():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=bind,target=/x,rw"}))
    assert m.readonly is False


def test_repeated_mount_flags_all_collected():
    mounts = validate_and_parse_run_flags(_instr({"mount": ["type=cache,target=/a", "type=tmpfs,target=/b"]}))
    assert [m.type for m in mounts] == ["cache", "tmpfs"]


def test_cache_defaults():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=cache,target=/var/cache/apt"}))
    assert m.sharing == "locked"
    assert m.readonly is False


def test_cache_sharing_values_validated():
    with pytest.raises(BuildError, match="invalid sharing"):
        validate_and_parse_run_flags(_instr({"mount": "type=cache,target=/c,sharing=nope"}))


def test_secret_default_target_from_id():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=secret,id=tok"}))
    assert m.target == "/run/secrets/tok"
    assert m.readonly is True


def test_secret_id_from_target_basename():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=secret,target=/run/secrets/tok"}))
    assert m.id == "tok"


def test_secret_without_id_or_target_rejected():
    with pytest.raises(BuildError, match="requires an id"):
        validate_and_parse_run_flags(_instr({"mount": "type=secret"}))


def test_ssh_default_id():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=ssh"}))
    assert m.id == "default"


def test_missing_target_rejected_with_lineno():
    with pytest.raises(BuildError, match=r"requires a target.*line 7"):
        validate_and_parse_run_flags(_instr({"mount": "type=tmpfs"}))


def test_unknown_mount_type_rejected():
    with pytest.raises(BuildError, match="type 'volume' is not supported"):
        validate_and_parse_run_flags(_instr({"mount": "type=volume,target=/x"}))


def test_unknown_mount_option_rejected():
    with pytest.raises(BuildError, match="unknown option 'wibble'"):
        validate_and_parse_run_flags(_instr({"mount": "type=bind,target=/x,wibble=1"}))


def test_mode_uid_gid_parsed():
    (m,) = validate_and_parse_run_flags(_instr({"mount": "type=cache,target=/c,mode=0700,uid=100,gid=200"}))
    assert m.mode == 0o700
    assert m.uid == 100
    assert m.gid == 200


def test_bad_mode_rejected():
    with pytest.raises(BuildError, match="invalid mode"):
        validate_and_parse_run_flags(_instr({"mount": "type=cache,target=/c,mode=zz"}))


# ── cache-hit path still validates flags ─────────────────────────────────────
def test_flag_validation_runs_before_cache_lookup():
    from types import SimpleNamespace

    from chroot_distro.helpers.build_engine import run_step

    engine = SimpleNamespace(current=object(), no_cache=False)
    with (
        patch.object(run_step, "cache_lookup", side_effect=AssertionError("cache consulted")),
        pytest.raises(BuildError, match="--badflag"),
    ):
        run_step.do_run(engine, _instr({"badflag": "1"}))


# ── session helpers ───────────────────────────────────────────────────────────
class _Engine:
    def __init__(self, tmp_path):
        self.build_dir = str(tmp_path / "ctx")
        self.tmp_root = str(tmp_path / "tmp")
        self.stages = {}
        self.secrets = {}
        self.ssh_sockets = {}
        os.makedirs(self.build_dir, exist_ok=True)
        os.makedirs(self.tmp_root, exist_ok=True)


class _Stage:
    def __init__(self, tmp_path):
        self.rootfs_dir = str(tmp_path / "rootfs")
        self.workdir = "/"
        os.makedirs(self.rootfs_dir, exist_ok=True)


@pytest.fixture
def env(tmp_path):
    return _Engine(tmp_path), _Stage(tmp_path)


def _mount(spec):
    (m,) = validate_and_parse_run_flags(_instr({"mount": spec}))
    return m


def test_empty_mounts_is_noop(env):
    engine, stage = env
    with run_mount_session(engine, stage, []) as extra_env:
        assert extra_env == {}


def test_bind_escape_rejected(env):
    """.. components are clamped inside the context, so ../../etc is not found."""
    engine, stage = env
    m = _mount("type=bind,target=/x,source=../../etc")
    with pytest.raises(BuildError, match="not found"), run_mount_session(engine, stage, [m]):
        pass


def test_bind_missing_source_rejected(env):
    engine, stage = env
    m = _mount("type=bind,target=/x,source=nope")
    with pytest.raises(BuildError, match="not found"), run_mount_session(engine, stage, [m]):
        pass


def test_bind_symlink_to_host_path_rejected(env, tmp_path):
    """A context symlink pointing at an absolute host path must not bind it (BUG-01)."""
    engine, stage = env
    victim = tmp_path / "host-secret.txt"
    victim.write_text("TOP SECRET")
    os.symlink(str(victim), os.path.join(engine.build_dir, "evil-link"))
    m = _mount("type=bind,target=/x,source=evil-link")
    with pytest.raises(BuildError, match="not found|escapes"), run_mount_session(engine, stage, [m]):
        pass


def test_bind_ro_mounted_and_unmounted(env):
    engine, stage = env
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    m = _mount("type=bind,target=/mnt/x,source=sub")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount") as su,
    ):
        with run_mount_session(engine, stage, [m]):
            sm.assert_called_once()
            args, kwargs = sm.call_args
            assert args[0] == os.path.join(engine.build_dir, "sub")
            assert args[1] == os.path.join(stage.rootfs_dir, "mnt/x")
            assert kwargs["options"] == "ro"
        su.assert_called_once_with(os.path.join(stage.rootfs_dir, "mnt/x"), holder=None)


def test_bind_rw_uses_scratch_copy(env):
    engine, stage = env
    src = os.path.join(engine.build_dir, "data")
    os.makedirs(src)
    with open(os.path.join(src, "f"), "w") as fh:
        fh.write("hello")
    m = _mount("type=bind,target=/x,source=data,rw")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            mounted_src = sm.call_args[0][0]
            assert mounted_src != src
            assert mounted_src.startswith(engine.tmp_root)
            assert os.path.isfile(os.path.join(mounted_src, "f"))
        # Scratch copy removed on teardown; source untouched.
        assert not os.path.exists(mounted_src)
        assert os.path.isfile(os.path.join(src, "f"))


def test_cache_dir_created_and_lock_held(env, tmp_path):
    engine, stage = env
    m = _mount("type=cache,target=/var/cache/apt")
    cache_root = str(tmp_path / "cacheroot")
    lock_calls = []

    class _FakeLock:
        def __init__(self, key, command="build"):
            self.key = key

        def __enter__(self):
            lock_calls.append(("enter", self.key))
            return self

        def release(self):
            lock_calls.append(("release", self.key))

    with (
        patch.object(run_mounts, "RUN_CACHE_DIR", cache_root),
        patch("chroot_distro.locking.RunCacheLock", _FakeLock),
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            cache_dir = sm.call_args[0][0]
            assert cache_dir.startswith(cache_root)
            assert os.path.isdir(cache_dir)
            assert lock_calls == [("enter", os.path.basename(cache_dir))]
        assert lock_calls[-1][0] == "release"


def test_cache_sharing_shared_takes_no_lock(env, tmp_path):
    engine, stage = env
    m = _mount("type=cache,target=/c,sharing=shared")
    with (
        patch.object(run_mounts, "RUN_CACHE_DIR", str(tmp_path / "cr")),
        patch("chroot_distro.locking.RunCacheLock") as lock_cls,
        patch("chroot_distro.helpers.mount_manager.safe_mount"),
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            pass
        lock_cls.assert_not_called()


def test_cache_sharing_private_uses_throwaway_copy(env, tmp_path):
    engine, stage = env
    cache_root = str(tmp_path / "cr")
    m = _mount("type=cache,target=/c,sharing=private,id=priv")
    with (
        patch.object(run_mounts, "RUN_CACHE_DIR", cache_root),
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            mounted_src = sm.call_args[0][0]
            assert mounted_src.startswith(engine.tmp_root)
        assert not os.path.exists(mounted_src)


def test_tmpfs_uses_special_mount(env):
    engine, stage = env
    m = _mount("type=tmpfs,target=/tmp/scratch,mode=1777")
    with (
        patch("chroot_distro.helpers.mount_manager.apply_special_mount") as asm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount") as su,
    ):
        with run_mount_session(engine, stage, [m]):
            asm.assert_called_once()
            sm_obj = asm.call_args[0][1]
            assert sm_obj.fstype == "tmpfs"
            assert sm_obj.target == "/tmp/scratch"
            assert sm_obj.options == "mode=1777"
            assert sm_obj.optional is False
        su.assert_called_once()


def test_secret_without_cli_secret_rejected(env):
    engine, stage = env
    m = _mount("type=secret,id=tok")
    with pytest.raises(BuildError, match="--secret id=tok"), run_mount_session(engine, stage, [m]):
        pass


def test_secret_materialised_0400_and_removed_on_teardown(env, tmp_path):
    engine, stage = env
    secret_src = tmp_path / "token.txt"
    secret_src.write_text("s3cr3t")
    engine.secrets["tok"] = str(secret_src)
    m = _mount("type=secret,id=tok")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            tmp_copy = sm.call_args[0][0]
            assert tmp_copy.startswith(engine.tmp_root)
            assert oct(os.stat(tmp_copy).st_mode & 0o777) == "0o400"
            assert sm.call_args[0][1] == os.path.join(stage.rootfs_dir, "run/secrets/tok")
            assert sm.call_args[1]["options"] == "ro"
        assert not os.path.exists(tmp_copy)


def test_secret_removed_on_step_failure(env, tmp_path):
    engine, stage = env
    secret_src = tmp_path / "token.txt"
    secret_src.write_text("s3cr3t")
    engine.secrets["tok"] = str(secret_src)
    m = _mount("type=secret,id=tok")
    tmp_copy_holder = {}
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        pytest.raises(RuntimeError),
        run_mount_session(engine, stage, [m]),
    ):
        tmp_copy_holder["p"] = sm.call_args[0][0]
        raise RuntimeError("step failed")
    assert not os.path.exists(tmp_copy_holder["p"])


def _placeholder_safe_mount(src, tgt, **kwargs):
    """Mimic the real safe_mount: create the missing mountpoint file/dirs."""
    os.makedirs(os.path.dirname(tgt), exist_ok=True)
    if os.path.isdir(src):
        os.makedirs(tgt, exist_ok=True)
    else:
        open(tgt, "a").close()


def test_created_mountpoint_removed_on_teardown(env, tmp_path):
    """Placeholder mountpoints must not leak into the layer (CI regression)."""
    engine, stage = env
    secret_src = tmp_path / "token.txt"
    secret_src.write_text("s3cr3t")
    engine.secrets["tok"] = str(secret_src)
    m = _mount("type=secret,id=tok")
    tgt = os.path.join(stage.rootfs_dir, "run/secrets/tok")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount", side_effect=_placeholder_safe_mount),
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            assert os.path.isfile(tgt)
    assert not os.path.exists(tgt)
    assert not os.path.exists(os.path.join(stage.rootfs_dir, "run"))


def test_preexisting_mountpoint_kept_on_teardown(env, tmp_path):
    engine, stage = env
    secret_src = tmp_path / "token.txt"
    secret_src.write_text("s3cr3t")
    engine.secrets["tok"] = str(secret_src)
    m = _mount("type=secret,id=tok")
    tgt = os.path.join(stage.rootfs_dir, "run/secrets/tok")
    os.makedirs(os.path.dirname(tgt))
    open(tgt, "a").close()
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount", side_effect=_placeholder_safe_mount),
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        pass
    assert os.path.isfile(tgt)


def test_created_dir_with_run_output_kept(env):
    """rmdir-only semantics: a dir the step wrote real files into stays."""
    engine, stage = env
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    m = _mount("type=bind,target=/mnt/x,source=sub")
    sibling = os.path.join(stage.rootfs_dir, "mnt/kept.txt")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount", side_effect=_placeholder_safe_mount),
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        with open(sibling, "w") as fh:
            fh.write("step output")
    assert not os.path.exists(os.path.join(stage.rootfs_dir, "mnt/x"))
    assert os.path.isfile(sibling)


def test_ssh_sets_auth_sock_env(env, tmp_path):
    engine, stage = env
    sock = tmp_path / "agent.sock"
    sock.write_text("")
    engine.ssh_sockets["default"] = str(sock)
    m = _mount("type=ssh")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]) as extra_env,
    ):
        target = extra_env["SSH_AUTH_SOCK"]
        assert target.startswith("/run/buildkit/ssh_agent.")
        assert sm.call_args[0][0] == str(sock)


def test_ssh_without_cli_flag_rejected(env):
    engine, stage = env
    m = _mount("type=ssh")
    with pytest.raises(BuildError, match="--ssh"), run_mount_session(engine, stage, [m]):
        pass


def test_target_traversal_rejected(env):
    engine, stage = env
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    m = _mount("type=bind,target=/../../x,source=sub")
    with pytest.raises(BuildError, match="invalid RUN --mount target"), run_mount_session(engine, stage, [m]):
        pass


def test_relative_target_joined_to_workdir(env):
    engine, stage = env
    stage.workdir = "/app"
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    m = _mount("type=bind,target=x,source=sub")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        assert sm.call_args[0][1] == os.path.join(stage.rootfs_dir, "app/x")


def test_bind_from_stage_rootfs(env, tmp_path):
    engine, stage = env

    class _Ref:
        rootfs_dir = str(tmp_path / "other-rootfs")

    os.makedirs(os.path.join(_Ref.rootfs_dir, "opt"), exist_ok=True)
    engine.stages["builder"] = _Ref()
    m = _mount("type=bind,target=/x,source=/opt,from=builder")
    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        assert sm.call_args[0][0] == os.path.join(_Ref.rootfs_dir, "opt")


# ── the target is a name the image can aim ────────────────────────────────────
def test_target_through_a_symlinked_leaf_stays_inside_the_rootfs(env, tmp_path):
    # safe_mount() makes the mountpoint with a named makedirs and mount(2)
    # resolves the name again, so a link standing at the target sent the source
    # wherever it pointed.
    engine, stage = env
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    os.symlink(str(outside), os.path.join(stage.rootfs_dir, "x"))
    m = _mount("type=bind,target=/x,source=sub")

    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        target = sm.call_args[0][1]

    assert target.startswith(stage.rootfs_dir + os.sep)
    assert os.listdir(str(outside)) == []


def test_target_follows_a_link_the_image_legitimately_ships(env):
    # `/var/run -> /run` is in nearly every distro image.
    engine, stage = env
    os.makedirs(os.path.join(engine.build_dir, "sub"))
    os.makedirs(os.path.join(stage.rootfs_dir, "var"))
    os.symlink("/run", os.path.join(stage.rootfs_dir, "var", "run"))
    m = _mount("type=bind,target=/var/run/x,source=sub")

    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        assert sm.call_args[0][1] == os.path.join(stage.rootfs_dir, "run/x")


def test_tmpfs_target_is_the_resolved_path(env):
    # apply_special_mount joins its target under the rootfs by name, so what it
    # is handed has to be the resolved one.
    engine, stage = env
    os.makedirs(os.path.join(stage.rootfs_dir, "var"))
    os.symlink("/run", os.path.join(stage.rootfs_dir, "var", "run"))
    m = _mount("type=tmpfs,target=/var/run/scratch")

    with (
        patch("chroot_distro.helpers.mount_manager.apply_special_mount") as asm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        run_mount_session(engine, stage, [m]),
    ):
        assert asm.call_args[0][1].target == "/run/scratch"


# ── what a step leaves in the scratch copy ────────────────────────────────────
def test_a_scratch_directory_the_step_sealed_still_goes(env):
    # The rw bind is the step's to write into, so the modes at teardown are its
    # choice. shutil.rmtree(ignore_errors=True) could not read a directory left
    # mode 0 and left the tree standing.
    engine, stage = env
    src = os.path.join(engine.build_dir, "data")
    os.makedirs(os.path.join(src, "sub"))
    m = _mount("type=bind,target=/x,source=data,rw")

    with (
        patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
        patch("chroot_distro.helpers.mount_manager.safe_unmount"),
    ):
        with run_mount_session(engine, stage, [m]):
            mounted_src = sm.call_args[0][0]
            os.chmod(os.path.join(mounted_src, "sub"), 0o000)
        assert not os.path.exists(mounted_src)


def test_the_scratch_removal_follows_the_pinned_root_not_the_name(env, tmp_path):
    # `tmp_root` is a name a process a previous step left behind can re-point;
    # the removal is made off the descriptor the build opened on it.
    engine, stage = env
    os.makedirs(os.path.join(engine.build_dir, "data"))
    engine.tmp_root_fd = dirfd.opendir(engine.tmp_root)
    m = _mount("type=bind,target=/x,source=data,rw")

    moved = str(tmp_path / "moved")
    decoy = tmp_path / "decoy-file"
    try:
        with (
            patch("chroot_distro.helpers.mount_manager.safe_mount") as sm,
            patch("chroot_distro.helpers.mount_manager.safe_unmount"),
        ):
            with run_mount_session(engine, stage, [m]):
                scratch = os.path.basename(sm.call_args[0][0])
                os.rename(engine.tmp_root, moved)
                os.mkdir(engine.tmp_root)
                os.mkdir(os.path.join(engine.tmp_root, scratch))
                decoy.write_text("kept")
                os.link(str(decoy), os.path.join(engine.tmp_root, scratch, "kept"))
    finally:
        os.close(engine.tmp_root_fd)

    assert not os.path.exists(os.path.join(moved, scratch))
    assert os.path.isfile(os.path.join(engine.tmp_root, scratch, "kept"))
