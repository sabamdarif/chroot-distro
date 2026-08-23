from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.commands.build import _resolve_build_isolation_mode
from chroot_distro.helpers import isolation
from chroot_distro.helpers.build_engine import run_step
from chroot_distro.helpers.namespace import NamespaceError


# ── env resolution ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " TRUE "])
def test_cd_use_isolation_maps_to_max(monkeypatch, value):
    monkeypatch.setenv("CD_USE_ISOLATION", value)
    monkeypatch.delenv("CD_USE_NS", raising=False)
    assert _resolve_build_isolation_mode() == "max"


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " On "])
def test_cd_use_ns_maps_to_ns(monkeypatch, value):
    monkeypatch.delenv("CD_USE_ISOLATION", raising=False)
    monkeypatch.setenv("CD_USE_NS", value)
    assert _resolve_build_isolation_mode() == "ns"


def test_both_set_isolation_wins(monkeypatch):
    monkeypatch.setenv("CD_USE_ISOLATION", "1")
    monkeypatch.setenv("CD_USE_NS", "1")
    assert _resolve_build_isolation_mode() == "max"


def test_neither_set_is_none(monkeypatch):
    monkeypatch.delenv("CD_USE_ISOLATION", raising=False)
    monkeypatch.delenv("CD_USE_NS", raising=False)
    assert _resolve_build_isolation_mode() == "none"


@pytest.mark.parametrize("value", ["0", "false", "off", "nope", ""])
def test_falsy_values_are_none(monkeypatch, value):
    monkeypatch.setenv("CD_USE_ISOLATION", value)
    monkeypatch.setenv("CD_USE_NS", value)
    assert _resolve_build_isolation_mode() == "none"


# ── _exec_chroot dispatch ─────────────────────────────────────────────────────
def _engine(mode, tmp_path):
    return SimpleNamespace(
        isolation_mode=mode,
        tmp_root=str(tmp_path),
        quiet=True,
        verbose=False,
        secrets={},
        ssh_sockets={},
        stages={},
        build_dir=str(tmp_path),
    )


def _stage(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir(exist_ok=True)
    return SimpleNamespace(
        rootfs_dir=str(rootfs),
        rootfs_fd=None,
        user="",
        workdir="/",
        index=0,
        env={},
        declared_args=set(),
        args={},
    )


def _dispatch(engine, stage):
    """Run _exec_chroot with everything below the dispatch stubbed out."""
    with (
        patch.object(run_step, "resolve_user_for_chroot", return_value=(0, 0)),
        patch("chroot_distro.commands.login.chroot_cmd.build_chroot_args", return_value=["chroot"]),
        patch("chroot_distro.commands.login.passwd.find_user_groups", return_value=[]),
        patch.object(run_step, "_run_plain", return_value=0) as run_plain,
        patch.object(run_step, "_run_in_holder", return_value=0) as run_in_holder,
    ):
        rc = run_step._exec_chroot(engine, stage, ["true"], None, [])
    return rc, run_plain, run_in_holder


def test_mode_none_uses_run_plain(tmp_path):
    engine = _engine("none", tmp_path)
    with (
        patch.object(isolation, "max_isolation_session") as max_sess,
        patch.object(isolation, "namespace_session") as ns_sess,
    ):
        rc, run_plain, run_in_holder = _dispatch(engine, _stage(tmp_path))
    assert rc == 0
    run_plain.assert_called_once()
    run_in_holder.assert_not_called()
    max_sess.assert_not_called()
    ns_sess.assert_not_called()


@pytest.mark.parametrize(
    ("mode", "used", "unused"),
    [("max", "max_isolation_session", "namespace_session"), ("ns", "namespace_session", "max_isolation_session")],
)
def test_mode_dispatches_to_right_session(tmp_path, mode, used, unused):
    engine = _engine(mode, tmp_path)
    holder = MagicMock()

    class _Session:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return holder

        def __exit__(self, *a):
            return False

    with (
        patch.object(isolation, used, _Session) ,
        patch.object(isolation, unused) as other,
    ):
        rc, run_plain, run_in_holder = _dispatch(engine, _stage(tmp_path))
    assert rc == 0
    run_in_holder.assert_called_once()
    run_plain.assert_not_called()
    other.assert_not_called()


@pytest.mark.parametrize("mode", ["max", "ns"])
def test_holder_none_falls_back_to_run_plain(tmp_path, mode):
    engine = _engine(mode, tmp_path)

    class _NoneSession:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return None

        def __exit__(self, *a):
            return False

    name = "max_isolation_session" if mode == "max" else "namespace_session"
    with patch.object(isolation, name, _NoneSession):
        rc, run_plain, run_in_holder = _dispatch(engine, _stage(tmp_path))
    assert rc == 0
    run_plain.assert_called_once()
    run_in_holder.assert_not_called()


# ── namespace_session ─────────────────────────────────────────────────────────
def _probe(missing_mandatory=(), has_userns=False):
    return SimpleNamespace(
        missing_mandatory=list(missing_mandatory),
        missing_recommended=[],
        missing_enhancements=[],
        userns_mounts_ok=True,
        has_userns=has_userns,
    )


def test_namespace_session_yields_none_without_mount_ns(tmp_path):
    with (
        patch.object(isolation, "probe_isolation", return_value=_probe(missing_mandatory=["mnt"])),
        patch.object(isolation.namespace, "acquire_holder") as acquire,
        patch.object(isolation, "warn"),
    ):
        with isolation.namespace_session("key", str(tmp_path)) as holder:
            assert holder is None
        acquire.assert_not_called()


def test_namespace_session_holder_not_chrooted_and_default_binds(tmp_path):
    holder = MagicMock()
    binds = [("/dev", str(tmp_path / "dev"))]
    with (
        patch.object(isolation, "probe_isolation", return_value=_probe()),
        patch.object(isolation.namespace, "acquire_holder", return_value=holder) as acquire,
        patch.object(isolation, "finalize_holder"),
        patch.object(isolation, "write_resolv_conf"),
        patch.object(isolation, "apply_special_mounts") as special,
        patch.object(isolation.mount_manager, "unmount_all"),
        patch.object(isolation.mount_manager, "safe_mount") as safe_mount,
        patch.object(isolation.mount_manager, "make_rslave"),
        patch.object(isolation, "_teardown") as teardown,
        patch("chroot_distro.commands.login.bindings.get_bindings", return_value=(binds, [])) as gb,
    ):
        with isolation.namespace_session("key", str(tmp_path)) as h:
            assert h is holder
        # Not chrooted: acquire_holder called without rootfs=.
        assert acquire.call_args == (("key",),)
        # Default mount set: isolated/max_isolation off, namespaces on.
        gb_kwargs = gb.call_args.kwargs
        assert gb_kwargs["isolated"] is False
        assert gb_kwargs["max_isolation"] is False
        assert gb_kwargs["use_namespaces"] is True
        sp_kwargs = special.call_args.kwargs
        assert sp_kwargs["isolated"] is False
        assert sp_kwargs["max_isolation"] is False
        safe_mount.assert_called_once()
        teardown.assert_called_once_with("key", str(tmp_path), holder)


def test_namespace_session_teardown_on_namespace_error(tmp_path):
    holder = MagicMock()
    with (
        patch.object(isolation, "probe_isolation", return_value=_probe()),
        patch.object(isolation.namespace, "acquire_holder", return_value=holder),
        patch.object(isolation, "finalize_holder", side_effect=NamespaceError("boom")),
        patch.object(isolation, "_teardown") as teardown,
        patch.object(isolation, "warn"),
    ):
        with isolation.namespace_session("key", str(tmp_path)) as h:
            assert h is None
        teardown.assert_called_once_with("key", str(tmp_path), holder)


def test_max_isolation_session_still_chroots_holder(tmp_path):
    # Contrast test: the max session passes rootfs= so the holder chroots.
    holder = MagicMock()
    with (
        patch.object(isolation, "probe_isolation", return_value=_probe()),
        patch.object(isolation.namespace, "acquire_holder", return_value=holder) as acquire,
        patch.object(isolation, "finalize_holder"),
        patch.object(isolation, "write_resolv_conf"),
        patch.object(isolation, "apply_special_mounts"),
        patch.object(isolation.mount_manager, "unmount_all"),
        patch.object(isolation, "_teardown"),
        patch("chroot_distro.commands.login.bindings.get_bindings", return_value=([], [])),
    ):
        with isolation.max_isolation_session("key", str(tmp_path)):
            pass
        assert acquire.call_args.kwargs["rootfs"] == str(tmp_path)


# ── engine validation ─────────────────────────────────────────────────────────
def test_engine_rejects_unknown_isolation_mode(tmp_path):
    from chroot_distro.helpers.build_engine.engine import BuildEngine

    with pytest.raises(ValueError, match="isolation_mode"):
        BuildEngine(
            build_dir=str(tmp_path),
            tmp_root=str(tmp_path),
            target_arch_pd="aarch64",
            user_build_args={},
            target_stage=None,
            verbose=False,
            quiet=True,
            no_cache=False,
            emulator=None,
            isolation_mode="bogus",
        )


def test_engine_default_mode_is_none(tmp_path):
    from chroot_distro.helpers.build_engine.engine import BuildEngine

    eng = BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path),
        target_arch_pd="aarch64",
        user_build_args={},
        target_stage=None,
        verbose=False,
        quiet=True,
        no_cache=False,
        emulator=None,
    )
    assert eng.isolation_mode == "none"
