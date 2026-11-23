import json
import os
import shlex
import subprocess
import sys
from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path
from importlib.machinery import ModuleSpec
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.elevate import (
    _find_escalation_tool,
    _forwarded_env,
    _find_termux_su,
    _su_help_text,
    _termux_su_argv,
    elevate_or_die,
    get_reexec_argv,
    is_root,
)
from chroot_distro.elevation_handoff import HANDOFF_ENV, _read_handoff, receive_handoff, send_handoff
from chroot_distro.exceptions import RootRequiredError


def test_is_root():
    with patch("os.geteuid", return_value=0):
        assert is_root() is True

    with patch("os.geteuid", return_value=1000):
        assert is_root() is False


def test_get_reexec_argv_absolute():
    # If sys.argv[0] is absolute and not .py, return as is
    with patch("sys.argv", ["/usr/bin/chroot-distro", "login", "alpine"]):
        argv = get_reexec_argv()
        assert argv == ["/usr/bin/chroot-distro", "login", "alpine"]


def test_get_reexec_argv_relative_resolved():
    # If sys.argv[0] is relative but in path, resolve it
    with (
        patch("sys.argv", ["chroot-distro", "login", "alpine"]),
        patch("shutil.which", return_value="/usr/local/bin/chroot-distro"),
    ):
        argv = get_reexec_argv()
        assert argv == ["/usr/local/bin/chroot-distro", "login", "alpine"]


def test_get_reexec_argv_python_script():
    # If sys.argv[0] ends with .py, prepend sys.executable
    with patch("sys.argv", ["/path/to/main.py", "list"]), patch("sys.executable", "/usr/bin/python3"):
        argv = get_reexec_argv()
        assert argv == ["/usr/bin/python3", "/path/to/main.py", "list"]


@pytest.mark.parametrize(
    "startup",
    [
        ["-S", "-X", "dev", "-m", "chroot_distro"],
        ["-Smchroot_distro"],
        ["-I", "-m", "chroot_distro.__main__"],
    ],
)
def test_get_reexec_argv_module(startup):
    app_args = ["run", "alpine", "--", "-m", "-X"]
    script = "/checkout/src/chroot_distro/__main__.py"
    spec = ModuleSpec("chroot_distro.__main__", loader=None, origin=script)
    with (
        patch("__main__.__spec__", spec),
        patch("sys.argv", [script, *app_args]),
        patch("sys.orig_argv", ["python3", *startup, *app_args]),
        patch("sys.executable", "/venv/bin/python3"),
    ):
        assert get_reexec_argv() == ["/venv/bin/python3", *startup, *app_args]


@pytest.mark.parametrize("ignore_environment", [0, 1])
def test_forwarded_env_only_carries_module_import_parent(tmp_path, monkeypatch, ignore_environment):
    parent = tmp_path / "src"
    script = parent / "chroot_distro" / "__main__.py"
    spec = ModuleSpec("chroot_distro.__main__", loader=None, origin=str(script))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(("src", "other")))
    with patch("__main__.__spec__", spec), patch("sys.flags", ignore_environment=ignore_environment):
        values = _forwarded_env()
    if ignore_environment:
        assert "PYTHONPATH" not in values
    else:
        assert values["PYTHONPATH"] == str(parent)


def test_forwarded_env_only_present_vars():
    with patch.dict(
        "os.environ",
        {"CD_USE_NS": "1", "CD_DOWNLOAD_WORKERS": "8", "UNRELATED": "x", "CD_DOCKER_AUTH": "user:pass"},
        clear=True,
    ):
        values = _forwarded_env()
    assert values == {"CD_USE_NS": "1", "CD_DOWNLOAD_WORKERS": "8"}


def test_forwarded_linux_env_preserves_storage_and_runtime_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = {
        "CD_BUILD_CACHE_MAX": "1G",
        "CD_USER": "guest",
        "CD_WORKDIR": "/some dir",
        "CD_ENTRYPOINT": "/bin/echo",
        "CD_NO_BINFMT": "1",
    }
    with patch.dict(os.environ, {**settings, "XDG_DATA_HOME": "data", "XDG_CACHE_HOME": ""}, clear=True):
        assert _forwarded_env() == {**settings, "XDG_DATA_HOME": str(tmp_path / "data")}


def test_android_host_vars_survive_elevation():
    """`su` may hand the root side an environment of its own, so the Android
    system vars the guest needs for `am`/termux-api are forwarded explicitly."""
    from chroot_distro.elevate import _termux_root_env_exports

    android = {
        "BOOTCLASSPATH": "/apex/com.android.art/javalib/core-oj.jar",
        "ANDROID_ART_ROOT": "/apex/com.android.art",
    }
    termux = {"TERMUX_APP__APP_VERSION_NAME": "0.119", "TERMUX_VERSION": "0.119", "CD_USER": "guest"}
    with (
        patch.dict("os.environ", {**android, **termux, "XDG_DATA_HOME": "/ignored"}, clear=True),
        patch("chroot_distro.elevate.TERMUX_APP_PACKAGE", "com.example"),
        patch("chroot_distro.elevate.TERMUX_HOME", "/path with space/home"),
        patch("chroot_distro.elevate.TERMUX_PREFIX", "/path with space/usr"),
        patch("os.makedirs"),
    ):
        prelude = _termux_root_env_exports()

    for key, value in {
        **android,
        **termux,
        "TERMUX_APP__PACKAGE_NAME": "com.example",
        "TERMUX__HOME": "/path with space/home",
        "TERMUX__PREFIX": "/path with space/usr",
    }.items():
        assert f"export {key}={shlex.quote(value)}" in prelude
    assert "XDG_DATA_HOME" not in prelude


@pytest.mark.parametrize(
    ("available", "expected"),
    [
        (("sudo", "doas", "pkexec", "su"), ["sudo", "-H", "-u", "root", "--"]),
        (("doas", "pkexec", "su"), ["doas", "--"]),
        (("pkexec", "su"), ["pkexec", "--disable-internal-agent"]),
        (("su",), ["su", "-c"]),
        ((), None),
    ],
)
def test_linux_tool_order(available, expected):
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in available else None):
        assert _find_escalation_tool() == expected


def test_elevation_loop_and_missing_tool(monkeypatch):
    monkeypatch.setattr("chroot_distro.elevate.IS_TERMUX", False)
    monkeypatch.setattr("chroot_distro.elevate._find_escalation_tool", lambda: None)
    with pytest.raises(RootRequiredError, match="no privilege elevation tool"):
        elevate_or_die(Namespace())
    monkeypatch.setenv("_CHROOT_DISTRO_ELEVATING", "1")
    with pytest.raises(RootRequiredError, match="Privilege elevation loop detected"):
        elevate_or_die(Namespace())


@pytest.mark.parametrize(
    "tool",
    [
        ["sudo", "-H", "-u", "root", "--"],
        ["doas", "--"],
        ["pkexec", "--disable-internal-agent"],
        ["su", "-c"],
    ],
)
def test_linux_bootstrap_restores_cwd_and_fixed_env(tool, tmp_path, monkeypatch):
    caller = tmp_path / "caller's directory"
    caller.mkdir()
    (caller / "context").write_text("relative content")
    root_home = tmp_path / "root-home"
    root_home.mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setenv("CD_USE_NS", "1")
    monkeypatch.setenv("XDG_CACHE_HOME", "cache")
    monkeypatch.setenv("CD_DOCKER_AUTH", "user:private-token")
    monkeypatch.setattr("chroot_distro.elevate.IS_TERMUX", False)
    monkeypatch.setattr("chroot_distro.elevate._find_escalation_tool", lambda: tool)
    monkeypatch.setattr(
        "chroot_distro.elevate.get_reexec_argv",
        lambda: [
            sys.executable,
            "-c",
            "import os; print(open('context').read()); print(os.environ['HOME']); "
            "print(os.environ['CD_USE_NS']); print(os.environ['XDG_CACHE_HOME'])",
        ],
    )
    monkeypatch.setattr("chroot_distro.elevate.send_handoff", lambda args: nullcontext("123:4:1000"))
    execvp = MagicMock()
    monkeypatch.setattr(os, "execvp", execvp)

    elevate_or_die(Namespace())
    argv = execvp.call_args.args[1]
    assert argv[: len(tool)] == tool
    bootstrap = shlex.split(argv[-1]) if tool[0] == "su" else argv[len(tool) :]
    assert bootstrap[:4] == [sys.executable, "-I", "-S", "-c"]
    assert "private-token" not in shlex.join(argv)
    assert json.loads(bootstrap[6])[HANDOFF_ENV] == "123:4:1000"

    run = subprocess.run(
        bootstrap, cwd=root_home, env={"HOME": str(root_home)}, capture_output=True, text=True, check=True
    )
    assert run.stdout.splitlines() == ["relative content", str(root_home), "1", str(caller / "cache")]
    caller.rename(tmp_path / "moved")
    run = subprocess.run(bootstrap, cwd=root_home, capture_output=True, text=True)
    assert run.returncode == 1
    assert run.stdout == ""
    assert "root re-entry failed" in run.stderr


def test_elevation_fails_before_launch_if_cwd_is_gone(monkeypatch):
    execvp = MagicMock()
    monkeypatch.setattr(os, "execvp", execvp)
    monkeypatch.setattr(os, "getcwd", MagicMock(side_effect=FileNotFoundError(2, "working directory removed")))
    with pytest.raises(RootRequiredError, match="working directory removed"):
        elevate_or_die(Namespace())
    execvp.assert_not_called()


def test_termux_candidate_selection(tmp_path, monkeypatch):
    names = ["stub", "denied", "ambiguous", "modern"]
    paths = {name: str(tmp_path / name) for name in names}
    for path in paths.values():
        Path(path).touch(mode=0o700)
    help_text = {
        paths["stub"]: "Termux does not supply tools for rooting",
        paths["denied"]: "su: not allowed",
        paths["ambiguous"]: "Usage: su [args]",
        paths["modern"]: "MagiskSU\nUsage: su [options] [--] [user [argument...]]",
    }
    monkeypatch.delenv("CD_SU_PATH", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr("chroot_distro.elevate._SU_SEARCH_PATHS", tuple(paths.values()) + (paths["modern"],))
    probe = MagicMock(side_effect=help_text.__getitem__)
    monkeypatch.setattr("chroot_distro.elevate._su_help_text", probe)
    assert _find_termux_su() == (paths["modern"], help_text[paths["modern"]])
    assert [call.args[0] for call in probe.call_args_list] == list(paths.values())
    monkeypatch.setenv("CD_SU_PATH", paths["ambiguous"])
    assert _find_termux_su() == (paths["ambiguous"], help_text[paths["ambiguous"]])
    monkeypatch.setenv("CD_SU_PATH", paths["denied"])
    assert _find_termux_su() is None
    monkeypatch.setenv("CD_SU_PATH", str(tmp_path / "absent"))
    assert _find_termux_su() is None


def test_termux_su_argv_modes(monkeypatch):
    positional = ("/system/bin/su", "usage: su [WHO [COMMAND...]]")
    assert _termux_su_argv(positional, "body") == ["/system/bin/su", "0", "/system/bin/sh", "-c", "body"]
    path = "/system/bin/su"
    flags = "MagiskSU\n --interactive\n --preserve-environment\n --target PID\n pid 0 means magisk global mount namespace"
    monkeypatch.delenv("CD_SU_MOUNT_MASTER", raising=False)
    assert _termux_su_argv((path, flags), "body", elevation=True) == [path, "--interactive", "-c", "body"]
    monkeypatch.setenv("CD_SU_MOUNT_MASTER", "1")
    assert _termux_su_argv((path, flags), "body", elevation=True) == [
        path, "--target", "0", "--interactive", "-c", "body"
    ]
    assert _termux_su_argv((path, "--mount-master"), "body", elevation=True) == [path, "--mount-master", "-c", "body"]
    with pytest.raises(RootRequiredError, match="global mount namespace"):
        _termux_su_argv((path, "--target PID"), "body", elevation=True)


@pytest.mark.parametrize("loader", ["libtermux-exec-ld-preload.so", "libtermux-exec.so"])
def test_termux_root_environment_and_failed_cd(loader, tmp_path, monkeypatch):
    caller = tmp_path / "caller"
    caller.mkdir()
    prefix = tmp_path / "prefix"
    (prefix / "lib").mkdir(parents=True)
    expected_loader = prefix / "lib" / loader
    expected_loader.touch()
    home = tmp_path / "home"
    monkeypatch.chdir(caller)
    monkeypatch.setattr("chroot_distro.elevate.IS_TERMUX", True)
    monkeypatch.setattr("chroot_distro.elevate.TERMUX_PREFIX", str(prefix))
    monkeypatch.setattr("chroot_distro.elevate.TERMUX_HOME", str(home))
    monkeypatch.setattr("chroot_distro.elevate._find_termux_su", lambda: ("/system/bin/su", "MagiskSU"))
    monkeypatch.setattr("chroot_distro.elevate.get_reexec_argv", lambda: [sys.executable, "-c", "print('ran')"])
    monkeypatch.setenv("LD_PRELOAD", "caller-loader")
    monkeypatch.setenv("LD_LIBRARY_PATH", "caller-library-path")
    execve = MagicMock()
    monkeypatch.setattr(os, "execve", execve)

    elevate_or_die(Namespace())
    _, argv, env = execve.call_args.args
    assert argv[:2] == ["/system/bin/su", "-c"]
    assert "LD_PRELOAD" not in env
    assert "LD_LIBRARY_PATH" not in env
    assert f"export LD_PRELOAD={shlex.quote(str(expected_loader))}" in argv[-1]
    assert f"export TMPDIR={shlex.quote(str(prefix / 'tmp'))}" in argv[-1]
    assert (home / ".suroot").is_dir()

    caller.rename(tmp_path / "moved")
    result = subprocess.run(["/bin/sh", "-c", argv[-1]], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "cd:" in result.stderr


def test_su_help_capture_is_bounded(tmp_path, monkeypatch):
    tool = tmp_path / "su"
    tool.write_text("#!/bin/sh\nprintf '%0100d' 0\n")
    tool.chmod(0o700)
    monkeypatch.setattr("chroot_distro.elevate._SU_HELP_LIMIT", 32)
    assert _su_help_text(str(tool)) is None


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0, reason="requires a Linux nonroot sender")
def test_handoff_pins_anonymous_file_and_reaps_keeper(monkeypatch):
    monkeypatch.setenv("CD_ENV", "a=1\nb=2")
    monkeypatch.setenv("PYTHONPATH", "build input")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/caller/agent")
    args = Namespace(build_args=["MISSING"], secrets=["id=PYTHONPATH"], ssh=["default"])
    with send_handoff(args) as ref:
        pid = int(ref.split(":")[0])
        assert json.loads(_read_handoff(ref)) == {
            "secrets": {"CD_ENV": "a=1\nb=2"},
            "build": {"PYTHONPATH": "build input", "SSH_AUTH_SOCK": "/caller/agent"},
        }
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"secrets":{"LD_PRELOAD":"loader"},"build":{}}',
        b'{"secrets":{"CD_ENV":"a\\u0000b"},"build":{}}',
        b'{"secrets":{},"build":{"S":3}}',
        b'[' * 10000,
        b' ' * (1024 * 1024 + 1),
        b'\xff',
    ],
)
def test_handoff_rejects_invalid_payload(monkeypatch, payload):
    monkeypatch.setenv(HANDOFF_ENV, "100:4:1000")
    monkeypatch.setattr("chroot_distro.elevation_handoff._read_handoff", lambda ref: payload)
    with pytest.raises(RootRequiredError, match="environment passed"):
        receive_handoff()
    assert HANDOFF_ENV not in os.environ


def test_handoff_ignores_legacy_path_and_rejects_paths(tmp_path, monkeypatch):
    private = tmp_path / "keep"
    private.write_text('{"secrets":{},"build":{}}')
    monkeypatch.setenv("CD_SECRET_FILE", str(private))
    monkeypatch.delenv(HANDOFF_ENV, raising=False)
    assert receive_handoff() == {}
    monkeypatch.setenv(HANDOFF_ENV, str(private))
    with pytest.raises(RootRequiredError, match="environment passed"):
        receive_handoff()
    assert private.is_file()


def test_uid_zero_dispatch_loads_credentials_and_keeps_build_values_inert(tmp_path, monkeypatch):
    from chroot_distro import cli
    from chroot_distro.commands.build import _parse_build_args, _parse_secret_opts, _parse_ssh_opts

    monkeypatch.setattr(cli, "IS_TERMUX", False)
    monkeypatch.setattr("chroot_distro.elevate.is_root", lambda: True)
    monkeypatch.setenv("_CHROOT_DISTRO_ELEVATING", "1")
    monkeypatch.setenv(HANDOFF_ENV, "100:4:1000")
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("CD_DOCKER_AUTH", "original")
    monkeypatch.setattr(
        "chroot_distro.elevation_handoff._read_handoff",
        lambda ref: json.dumps({
            "secrets": {"CD_DOCKER_AUTH": "user:token"},
            "build": {"PYTHONPATH": "secret data", "SSH_AUTH_SOCK": "agent.sock", "EMPTY": ""},
        }).encode(),
    )

    def build(args):
        env = args._build_env
        assert os.environ["CD_DOCKER_AUTH"] == "user:token"
        assert os.environ.get("PYTHONPATH") != "secret data"
        assert HANDOFF_ENV not in os.environ
        assert _parse_build_args(args.build_args, env) == {"HOME": "", "EMPTY": ""}
        secret = _parse_secret_opts(args.secrets, str(tmp_path), env)["PYTHONPATH"]
        assert Path(secret).read_text() == "secret data"
        assert _parse_ssh_opts(args.ssh, env) == {"default": str(tmp_path / "agent.sock")}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(cli._COMMAND_HANDLERS, "build", build)
    monkeypatch.setattr(
        sys, "argv", ["chroot-distro", "build", "--build-arg", "HOME", "--build-arg", "EMPTY", "--secret", "id=PYTHONPATH", "--ssh"]
    )
    cli.main()
