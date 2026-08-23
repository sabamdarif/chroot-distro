# Containment tests for the environment a RUN step's host-side exec is handed.
#
# A RUN step execs the host's `chroot` binary, and chroot passes its own
# environment on to the command inside the new root: one dict, two masters. So a
# name that means "a setting for the container" to whoever wrote it means "a
# setting for the process that has not entered the rootfs yet" to the host's
# dynamic loader. The argv gives chroot `.` and the child fchdirs onto the stage
# rootfs between the fork and the exec, so a *relative* LD_LIBRARY_PATH or
# LD_AUDIT entry names a directory an earlier RUN step had the run of: a step
# dropping a library under `lib/`, then `ENV LD_LIBRARY_PATH=lib` on any later
# step, is the guest's code running as the invoking user outside any container.
#
# The rule is about provenance, not about the name. The user's own environment
# still reaches the exec, because they already chose this command line.

from types import SimpleNamespace

import pytest

from chroot_distro.helpers.build_engine import run_step
from chroot_distro.helpers.build_engine.constants import is_host_exec_var
from chroot_distro.helpers.build_engine.handlers import do_env


# ── the predicate ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "key",
    ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_BIND_NOW", "LD_SOMETHING_LIBC_ADDS_LATER"],
)
def test_the_loaders_namespace_is_matched_by_prefix(key):
    # A list would go stale: the one that existed here was LD_PRELOAD alone,
    # with LD_LIBRARY_PATH and LD_AUDIT reaching the exec untouched.
    assert is_host_exec_var(key)


@pytest.mark.parametrize("key", ["LANG", "PATH", "HOME", "TERM", "LDAP_URI", "LDFLAGS"])
def test_an_ordinary_name_is_not(key):
    assert not is_host_exec_var(key)


# ── the env the exec is handed ────────────────────────────────────────────────
def _child_env(env=None, args=None):
    stage = SimpleNamespace(env=dict(env or {}), args=dict(args or {}))
    stage.declared_args = set(stage.args)
    engine = SimpleNamespace(warned_host_exec=set())
    return run_step._build_child_env(engine, stage), engine


def test_a_dockerfile_env_cannot_reach_the_host_side_exec():
    env, _engine = _child_env(
        {
            "LD_LIBRARY_PATH": "lib",
            "LD_AUDIT": "lib/audit.so",
            "LD_PRELOAD": "/evil/pre.so",
            "SAFE": "1",
        }
    )
    for key in ("LD_LIBRARY_PATH", "LD_AUDIT", "LD_PRELOAD"):
        assert key not in env
    assert env["SAFE"] == "1"


def test_a_declared_arg_is_the_same_door():
    env, _engine = _child_env(args={"LD_AUDIT": "lib/audit.so", "OK": "2"})
    assert "LD_AUDIT" not in env
    assert env["OK"] == "2"


def test_the_users_own_loader_settings_are_not_this_functions_business(monkeypatch):
    # Whatever the invoking environment says is the user's own choice about
    # their own command; only a value out of the Dockerfile is refused. Nothing
    # here copies os.environ wholesale, so the name simply does not appear.
    monkeypatch.setenv("LD_LIBRARY_PATH", "/host/lib")
    env, _engine = _child_env()
    assert "LD_LIBRARY_PATH" not in env


def test_the_dockerfiles_own_path_still_decides_the_guests():
    # PATH is the guest's to set and deliberately not refused: the exec it
    # decides happens after chroot(2), so it can only pick a binary out of the
    # tree the step was given.
    env, _engine = _child_env({"PATH": "/opt/bin"})
    assert env["PATH"] == "/opt/bin"


def test_a_predefined_arg_from_the_host_still_reaches_the_step(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy:3128")
    env, _engine = _child_env()
    assert env["HTTP_PROXY"] == "http://proxy:3128"


def test_the_refusal_is_reported_once_per_build(capsys):
    stage = SimpleNamespace(env={"LD_LIBRARY_PATH": "lib"}, args={}, declared_args=set())
    engine = SimpleNamespace(warned_host_exec=set())
    run_step._build_child_env(engine, stage)
    run_step._build_child_env(engine, stage)
    out = capsys.readouterr()
    assert (out.err + out.out).count("LD_LIBRARY_PATH") == 1
    assert engine.warned_host_exec == {"LD_LIBRARY_PATH"}


# ── ENV, and where it came from ───────────────────────────────────────────────
def _engine_for_env(*, firing_onbuild):
    stage = SimpleNamespace(image_config={"config": {}}, env={})
    return SimpleNamespace(current=stage, firing_onbuild=firing_onbuild), stage


def _env_instr(value):
    return {"name": "ENV", "value": value, "exec_form": False, "lineno": 1}


def test_the_authors_own_env_reaches_the_image_config():
    engine, stage = _engine_for_env(firing_onbuild=False)
    do_env(engine, _env_instr("LD_LIBRARY_PATH=/opt/lib"))
    # What the Dockerfile says about the image it produces is its author's
    # business; only the host-side exec is refused it.
    assert stage.image_config["config"]["Env"] == ["LD_LIBRARY_PATH=/opt/lib"]
    assert stage.env["LD_LIBRARY_PATH"] == "/opt/lib"


def test_an_onbuild_env_from_the_base_image_is_dropped(capsys):
    # A trigger that fires is always the base image's: an ONBUILD in this
    # Dockerfile only records one for whoever builds FROM the result.
    engine, stage = _engine_for_env(firing_onbuild=True)
    do_env(engine, _env_instr("LD_AUDIT=lib/audit.so KEEP=1"))
    assert stage.image_config["config"]["Env"] == ["KEEP=1"]
    assert "LD_AUDIT" not in stage.env
    out = capsys.readouterr()
    assert "LD_AUDIT" in out.err + out.out
