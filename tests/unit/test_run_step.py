# Tests for the RUN step's idea of when a step is over. The command exiting is
# not the end of it: a `RUN cmd &` or a `RUN service x start` leaves a process
# writing into the stage rootfs the layer is diffed from, holding the step's
# bind mounts so the teardown cannot unmount them, and running long after the
# build. The CD_USE_NS / CD_USE_ISOLATION paths get this from the pid namespace
# the holder leads; the default path has to sweep for it.

import ctypes
import os
import subprocess
import sys
import time

import pytest

from chroot_distro.helpers.build_engine import run_step


@pytest.fixture(autouse=True)
def _drop_subreaper():
    """Clear the subreaper flag these tests set on the pytest process.

    PR_SET_CHILD_SUBREAPER is process-wide and outlives the test that asked for
    it, which changes where every later orphan in this process lands -- `kill`'s
    process-tree walk is one of the things that notices.
    """
    yield
    run_step._become_subreaper.cache_clear()
    try:
        ctypes.CDLL(None, use_errno=True).prctl(run_step._PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
    except (OSError, AttributeError, ValueError):
        pass


@pytest.fixture
def subreaper():
    """The flag that puts a step's orphans back within reach."""
    if not run_step._become_subreaper():
        pytest.skip("kernel refuses PR_SET_CHILD_SUBREAPER")
    return True


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    # A reaped zombie is gone; an unreaped one still answers.
    try:
        with open(f"/proc/{pid}/stat") as fh:
            fields = fh.read()
        return fields[fields.rindex(")") + 1 :].split()[0] != "Z"
    except (OSError, ValueError, IndexError):
        return False


def _wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_a_step_that_ends_cleanly_leaves_nothing_to_stop(subreaper):
    baseline = set(run_step._adopted())
    proc = subprocess.Popen(["sh", "-c", "exit 5"], start_new_session=True)
    assert proc.wait() == 5

    assert run_step._stop_step(proc.pid, baseline) == 0


def test_a_backgrounded_leftover_is_stopped_after_the_command_exits(subreaper, capsys):
    baseline = set(run_step._adopted())
    proc = subprocess.Popen(
        ["sh", "-c", "sleep 300 & exit 0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert proc.wait() == 0

    assert run_step._stop_step(proc.pid, baseline) >= 1
    assert run_step._leftovers(proc.pid, baseline, None) == []
    assert "left 1 process" in capsys.readouterr().err


def test_a_daemonised_leftover_is_found_through_adoption(subreaper):
    # fork, setsid, fork -- the sequence every daemon uses, which leaves the
    # step's process group as well as its process tree. Only the reparenting the
    # subreaper flag buys names it at all.
    baseline = set(run_step._adopted())
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import subprocess, sys;"
            "subprocess.Popen([sys.executable, '-c',"
            "'import os, time; os.setsid(); time.sleep(300)'])",
        ],
        check=True,
    )
    assert _wait_until(lambda: bool(run_step._adopted(baseline))), "the daemonised process was not reparented here"
    pid = run_step._adopted(baseline)[0]

    # Its own group, not the step's -- there is no step group here at all.
    # Passing this process's own pgid is what a caller must never be able to
    # turn into a signal: _leftovers refuses it and answers from adoption alone,
    # which is the half this test is about.
    assert run_step._stop_step(os.getpgrp(), baseline, quiet=True) >= 1
    assert _wait_until(lambda: not _alive(pid))


def test_this_processs_own_group_is_never_a_target(subreaper):
    # The whole pytest process group would otherwise be in the list, and the
    # answer to a caller passing the wrong pgid must not be a SIGTERM to
    # everything sharing a terminal with the build.
    baseline = set(run_step._adopted())

    assert run_step._leftovers(os.getpgrp(), baseline, None) == []


def test_a_leftover_holding_the_group_open_is_killed_when_it_ignores_sigterm(subreaper, monkeypatch):
    monkeypatch.setattr(run_step, "_STRAY_GRACE_SECONDS", 0.2)
    baseline = set(run_step._adopted())
    proc = subprocess.Popen(
        [sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"],
        start_new_session=True,
    )
    try:
        assert run_step._stop_step(proc.pid, baseline, quiet=True) == 1
        assert _wait_until(lambda: not _alive(proc.pid))
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


# ── the emulator gate ─────────────────────────────────────────────────────────
# `build`'s preflight reads the Dockerfile's RUN lines, so a step a base image's
# ONBUILD fired is the one that reaches an exec unannounced. This is where it is
# caught, which is also why a native stage must not pay for the question.
def _gate_pair(stage_arch, build_arch):
    from types import SimpleNamespace

    from chroot_distro.arch import platform_from_arch

    engine = SimpleNamespace(build_platform=platform_from_arch(build_arch))
    stage = SimpleNamespace(platform=platform_from_arch(stage_arch))
    return engine, stage


def test_a_foreign_step_without_a_handler_is_refused_at_the_exec(monkeypatch):
    from chroot_distro.helpers.build_engine.errors import BuildError

    monkeypatch.setattr(
        run_step, "ensure_handler", lambda _arch: (None, "no QEMU user-mode emulator for 'aarch64' is installed")
    )
    engine, stage = _gate_pair("aarch64", "x86_64")

    with pytest.raises(BuildError) as exc:
        run_step._require_emulator(engine, stage)

    assert "no emulator was registered" in str(exc.value)
    assert "aarch64" in str(exc.value)


def test_a_foreign_step_with_a_handler_goes_ahead(monkeypatch):
    monkeypatch.setattr(run_step, "ensure_handler", lambda arch: (f"/usr/bin/qemu-{arch}", ""))
    engine, stage = _gate_pair("aarch64", "x86_64")

    run_step._require_emulator(engine, stage)


def test_a_native_step_never_asks_for_a_handler(monkeypatch):
    def unexpected(_arch):
        raise AssertionError("a native stage asked for an emulator")

    monkeypatch.setattr(run_step, "ensure_handler", unexpected)
    engine, stage = _gate_pair("x86_64", "x86_64")

    run_step._require_emulator(engine, stage)
