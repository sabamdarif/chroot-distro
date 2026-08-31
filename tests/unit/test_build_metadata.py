# The instructions that only edit the image config, and the config a stage takes
# from its base. Nothing here runs a check or an entrypoint: what these write is
# what a runtime pulling the image reads, so a flag dropped on the way in is an
# image that does not say what its Dockerfile said.

from types import SimpleNamespace

import pytest

from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.handlers import HANDLERS
from chroot_distro.helpers.dockerfile import parse_dockerfile


def _engine():
    stage = SimpleNamespace(
        image_config={"config": {}},
        env={},
        args={},
        declared_args=set(),
        shell=["/bin/sh", "-c"],
        user="",
        workdir="/",
    )
    return SimpleNamespace(current=stage, firing_onbuild=False)


def _run(engine, text):
    """Dispatch every instruction in *text* through its handler; return the config."""
    _, instructions = parse_dockerfile(text)
    for instr in instructions:
        HANDLERS[instr["name"]](engine, instr)
    return engine.current.image_config["config"]


def _config(text):
    return _run(_engine(), text)


# ── HEALTHCHECK ───────────────────────────────────────────────────────────────
def test_a_shell_form_check_runs_through_a_shell():
    assert _config("HEALTHCHECK CMD curl -f http://localhost/\n")["Healthcheck"] == {
        "Test": ["CMD-SHELL", "curl -f http://localhost/"]
    }


def test_an_exec_form_check_is_the_command_itself():
    assert _config('HEALTHCHECK CMD ["curl", "-f", "http://x/"]\n')["Healthcheck"] == {
        "Test": ["CMD", "curl", "-f", "http://x/"]
    }


def test_a_json_array_that_is_not_all_strings_is_text_for_a_shell():
    assert _config("HEALTHCHECK CMD [1, 2]\n")["Healthcheck"]["Test"] == ["CMD-SHELL", "[1, 2]"]


def test_none_clears_the_inherited_check():
    assert _config("HEALTHCHECK NONE\n")["Healthcheck"] == {"Test": ["NONE"]}


def test_the_options_are_recorded_as_nanoseconds():
    # Not enforced here, but the image tells whoever runs it what to do with it.
    check = _config(
        "HEALTHCHECK --interval=30s --timeout=5s --start-period=1m "
        "--start-interval=2s --retries=3 CMD /healthy\n"
    )["Healthcheck"]
    assert check == {
        "Test": ["CMD-SHELL", "/healthy"],
        "Interval": 30_000_000_000,
        "Timeout": 5_000_000_000,
        "StartPeriod": 60_000_000_000,
        "StartInterval": 2_000_000_000,
        "Retries": 3,
    }


def test_a_zero_option_is_left_out_because_zero_means_inherit():
    assert _config("HEALTHCHECK --interval=0 --retries=0 CMD /healthy\n")["Healthcheck"] == {
        "Test": ["CMD-SHELL", "/healthy"]
    }


@pytest.mark.parametrize(
    ("line", "match"),
    [
        ("HEALTHCHECK CMD\n", "needs a command"),
        ("HEALTHCHECK PROBE /x\n", "'NONE' or 'CMD"),
        ("HEALTHCHECK NONE /x\n", "takes no arguments"),
        ("HEALTHCHECK --interval=5s NONE\n", "takes no arguments"),
        ("HEALTHCHECK --interval=nope CMD /x\n", "not a duration"),
        ("HEALTHCHECK --interval=100us CMD /x\n", "less than 1ms"),
        ("HEALTHCHECK --retries=many CMD /x\n", "not a count"),
        ("HEALTHCHECK --frobnicate=1 CMD /x\n", "not supported"),
    ],
)
def test_what_a_healthcheck_refuses(line, match):
    with pytest.raises(BuildError, match=match):
        _config(line)


# ── SHELL, CMD and ENTRYPOINT ─────────────────────────────────────────────────
def test_shell_must_be_json_and_changes_what_a_shell_form_cmd_wraps():
    engine = _engine()
    cfg = _run(engine, 'SHELL ["/bin/bash", "-lc"]\nCMD echo hi\n')
    assert cfg["Shell"] == ["/bin/bash", "-lc"]
    assert engine.current.shell == ["/bin/bash", "-lc"]
    assert cfg["Cmd"] == ["/bin/bash", "-lc", "echo hi"]


def test_a_shell_that_is_not_json_is_refused():
    with pytest.raises(BuildError, match="JSON exec form"):
        _config("SHELL /bin/bash -lc\n")


def test_an_entrypoint_clears_the_inherited_cmd():
    # Docker's rule, not an oversight: a Dockerfile wanting both puts CMD after.
    cfg = _config('CMD ["a"]\nENTRYPOINT ["/entry"]\n')
    assert cfg["Entrypoint"] == ["/entry"]
    assert cfg["Cmd"] is None


# ── the rest of the metadata ──────────────────────────────────────────────────
def test_expose_defaults_to_tcp_and_keeps_a_named_protocol():
    assert _config("EXPOSE 80 53/udp\n")["ExposedPorts"] == {"80/tcp": {}, "53/udp": {}}


def test_volume_takes_both_forms():
    assert _config('VOLUME /data\nVOLUME ["/log", "/spool"]\n')["Volumes"] == {
        "/data": {},
        "/log": {},
        "/spool": {},
    }


def test_label_and_maintainer_share_the_map():
    cfg = _config("MAINTAINER someone\nLABEL a=1 b=2\n")
    assert cfg["Labels"] == {"maintainer": "someone", "a": "1", "b": "2"}


def test_stopsignal_and_user_are_recorded():
    engine = _engine()
    cfg = _run(engine, "STOPSIGNAL SIGTERM\nUSER app:app\n")
    assert cfg["StopSignal"] == "SIGTERM"
    assert cfg["User"] == "app:app"
    assert engine.current.user == "app:app"
