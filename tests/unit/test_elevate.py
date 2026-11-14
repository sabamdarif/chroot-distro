import json
import os
import shlex
import tempfile
from importlib.machinery import ModuleSpec
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.elevate import (
    _find_escalation_tool,
    _forwarded_env,
    _load_secret_file,
    _write_secret_file,
    elevate_or_die,
    get_reexec_argv,
    is_root,
)
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


@patch("chroot_distro.elevate.IS_TERMUX", False)
def test_find_escalation_tool_linux():
    # Linux: sudo -> doas -> pkexec -> su
    # 1. sudo available
    with patch(
        "shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("sudo", "doas", "pkexec", "su") else None
    ):
        assert _find_escalation_tool() == ["sudo", "-E", "-H", "-u", "root", "--"]

    # 2. doas available (no sudo)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("doas", "pkexec", "su") else None):
        assert _find_escalation_tool() == ["doas", "--"]

    # 3. pkexec available (no sudo, no doas)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd in ("pkexec", "su") else None):
        assert _find_escalation_tool() == ["pkexec", "--disable-internal-agent"]

    # 4. su available (no sudo, doas, pkexec)
    with patch("shutil.which", side_effect=lambda cmd: "/usr/bin/" + cmd if cmd == "su" else None):
        assert _find_escalation_tool() == ["su", "-c"]

    # 5. none available
    with patch("shutil.which", return_value=None):
        assert _find_escalation_tool() is None


def test_elevate_or_die_already_root():
    with patch("chroot_distro.elevate.is_root", return_value=True), patch("os.execvp") as mock_exec:
        elevate_or_die()
        mock_exec.assert_not_called()


def test_elevate_or_die_loop_detected():
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch.dict("os.environ", {"_CHROOT_DISTRO_ELEVATING": "1"}),
        pytest.raises(RootRequiredError, match="Privilege elevation loop detected"),
    ):
        elevate_or_die()


def test_elevate_or_die_no_tool():
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=None),
        pytest.raises(RootRequiredError, match="requires root privileges, but no privilege elevation tool"),
    ):
        elevate_or_die()


def test_elevate_or_die_exec_sudo():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["sudo", "-E", "-H", "-u", "root", "--"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "alpine"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {}, clear=True),
    ):
        elevate_or_die()

        mock_exec.assert_called_once()
        args, _kwargs = mock_exec.call_args
        assert args[0] == "sudo"
        # The loop sentinel is always forwarded via the `env` prefix so it
        # survives a stripped environment.
        assert args[1] == [
            "sudo",
            "-E",
            "-H",
            "-u",
            "root",
            "--",
            "env",
            "_CHROOT_DISTRO_ELEVATING=1",
            "/usr/bin/chroot-distro",
            "login",
            "alpine",
        ]
        assert os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1"


def test_elevate_or_die_exec_su():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["su", "-c"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "alpine"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {}, clear=True),
    ):
        elevate_or_die()

        mock_exec.assert_called_once()
        args, _kwargs = mock_exec.call_args
        assert args[0] == "su"
        # su -c gets a single command string with the env prefix embedded.
        assert args[1] == [
            "su",
            "-c",
            "env _CHROOT_DISTRO_ELEVATING=1 /usr/bin/chroot-distro login alpine",
        ]
        assert os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1"


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


def test_elevate_forwards_cd_use_ns_via_sudo():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["sudo", "-E", "-H", "-u", "root", "--"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "ubuntu"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {"CD_USE_NS": "1"}, clear=True),
    ):
        elevate_or_die()

    args, _kwargs = mock_exec.call_args
    full_argv = args[1]
    assert "env" in full_argv
    assert "CD_USE_NS=1" in full_argv
    # The forwarded assignments must precede the re-exec'd program.
    assert full_argv.index("CD_USE_NS=1") < full_argv.index("/usr/bin/chroot-distro")


@pytest.mark.parametrize(
    "tool_cmd",
    [
        ["doas", "--"],
        ["pkexec", "--disable-internal-agent"],
    ],
)
def test_elevate_forwards_cd_use_ns_via_other_tools(tool_cmd):
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=tool_cmd),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "ubuntu"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {"CD_USE_NS": "yes"}, clear=True),
    ):
        elevate_or_die()

    args, _kwargs = mock_exec.call_args
    full_argv = args[1]
    assert full_argv[: len(tool_cmd)] == tool_cmd
    assert "env" in full_argv
    assert "CD_USE_NS=yes" in full_argv
    assert full_argv.index("CD_USE_NS=yes") < full_argv.index("/usr/bin/chroot-distro")


def test_elevate_forwards_cd_use_ns_via_su():
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["su", "-c"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "login", "ubuntu"]),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {"CD_USE_NS": "1"}, clear=True),
    ):
        elevate_or_die()

    args, _kwargs = mock_exec.call_args
    cmd_str = args[1][2]
    assert "env" in cmd_str
    assert "CD_USE_NS=1" in cmd_str
    # Sentinel + CD_USE_NS appear before the program inside the command string.
    assert cmd_str.index("CD_USE_NS=1") < cmd_str.index("/usr/bin/chroot-distro")


def test_elevate_termux_stub_su():
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate.IS_TERMUX", True),
        patch("chroot_distro.elevate._find_termux_su", return_value="/data/data/com.termux/files/usr/bin/su"),
        patch(
            "chroot_distro.elevate._su_help_text",
            return_value="No su program found on this device. Termux does not supply tools for rooting",
        ),
        pytest.raises(RootRequiredError, match="the 'su' command on this device is a Termux stub"),
    ):
        elevate_or_die()


def test_is_root_available_already_root():
    from chroot_distro.elevate import is_root_available

    with patch("chroot_distro.elevate.is_root", return_value=True):
        assert is_root_available() is True


@patch("chroot_distro.elevate.IS_TERMUX", True)
def test_is_root_available_termux():
    from chroot_distro.elevate import is_root_available

    # 1. su is found and works
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_termux_su", return_value="/system/bin/su"),
        patch("chroot_distro.elevate._su_help_text", return_value="su version 3.0"),
    ):
        assert is_root_available() is True

    # 2. su is not found
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_termux_su", return_value=None),
    ):
        assert is_root_available() is False

    # 3. su is termux stub
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_termux_su", return_value="/system/bin/su"),
        patch(
            "chroot_distro.elevate._su_help_text",
            return_value="No su program found on this device. Termux does not supply tools for rooting",
        ),
    ):
        assert is_root_available() is False


@patch("chroot_distro.elevate.IS_TERMUX", False)
def test_is_root_available_linux():
    from chroot_distro.elevate import is_root_available

    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["sudo"]),
    ):
        assert is_root_available() is True

    # 3. no capabilities and no fallback tool
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=None),
    ):
        assert is_root_available() is False


# ---------------------------------------------------------------------------
# BUG-03: CD_DOCKER_AUTH must never appear in argv
# ---------------------------------------------------------------------------


def test_write_secret_file_none_when_no_secrets():
    with patch.dict("os.environ", {}, clear=True):
        assert _write_secret_file() is None


def test_load_secret_file_reads_and_unlinks():
    fd, path = tempfile.mkstemp(prefix=".cd-test-secret-")
    with os.fdopen(fd, "w") as f:
        json.dump({"CD_DOCKER_AUTH": "alice:mytoken"}, f)
    saved = os.environ.pop("CD_DOCKER_AUTH", None)
    os.environ["CD_SECRET_FILE"] = path
    try:
        _load_secret_file()
        assert os.environ.get("CD_DOCKER_AUTH") == "alice:mytoken"
        assert not os.path.exists(path)
    finally:
        os.environ.pop("CD_DOCKER_AUTH", None)
        os.environ.pop("CD_SECRET_FILE", None)
        if saved is not None:
            os.environ["CD_DOCKER_AUTH"] = saved
        try:
            os.unlink(path)
        except OSError:
            pass


def test_secret_file_round_trips_multiline_cd_env():
    """CD_ENV holds one VAR=VALUE per line; its newlines must survive."""
    cd_env = "PATH=/opt/bin:/usr/bin\nGITHUB_TOKEN=s3cret"
    with patch.dict("os.environ", {"CD_ENV": cd_env}, clear=True):
        path = _write_secret_file()
        assert path is not None
        os.environ["CD_SECRET_FILE"] = path
        _load_secret_file()
        assert os.environ["CD_ENV"] == cd_env
        assert not os.path.exists(path)


def test_load_secret_file_noop_when_unset():
    with patch.dict("os.environ", {}, clear=True):
        _load_secret_file()  # must not raise


def test_docker_auth_not_in_sudo_argv():
    """CD_DOCKER_AUTH must travel via tempfile path, not raw value in argv."""
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["sudo", "-E", "-H", "-u", "root", "--"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "install", "img"]),
        patch("chroot_distro.elevate._write_secret_file", return_value="/tmp/.cd-secret-test"),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {"CD_DOCKER_AUTH": "alice:s3cret"}, clear=True),
    ):
        elevate_or_die()

    args, _ = mock_exec.call_args
    full_argv = args[1]
    assert not any("s3cret" in a for a in full_argv), "raw secret must not appear in argv"
    assert "CD_SECRET_FILE=/tmp/.cd-secret-test" in full_argv


def test_docker_auth_not_in_su_argv():
    """Secret must not appear in su -c command string either."""
    mock_exec = MagicMock()
    with (
        patch("chroot_distro.elevate.is_root", return_value=False),
        patch("chroot_distro.elevate._find_escalation_tool", return_value=["su", "-c"]),
        patch("chroot_distro.elevate.get_reexec_argv", return_value=["/usr/bin/chroot-distro", "install", "img"]),
        patch("chroot_distro.elevate._write_secret_file", return_value="/tmp/.cd-secret-test"),
        patch("os.execvp", mock_exec),
        patch.dict("os.environ", {"CD_DOCKER_AUTH": "alice:s3cret"}, clear=True),
    ):
        elevate_or_die()

    args, _ = mock_exec.call_args
    cmd_str = args[1][2]  # su -c "<cmd_str>"
    assert "s3cret" not in cmd_str, "raw secret must not appear in su -c command string"
    assert "CD_SECRET_FILE=/tmp/.cd-secret-test" in cmd_str


def test_secret_file_ignores_unexpected_keys():
    """The file path arrives as a client-forwarded CD_* var: only the vars this
    channel exists for may be set on the root side."""
    fd, path = tempfile.mkstemp(prefix=".cd-test-secret-")
    with os.fdopen(fd, "w") as f:
        json.dump({"LD_PRELOAD": "/tmp/evil.so", "CD_DOCKER_AUTH": "alice:tok"}, f)
    with patch.dict("os.environ", {"CD_SECRET_FILE": path}, clear=True):
        _load_secret_file()
        assert "LD_PRELOAD" not in os.environ
        assert os.environ["CD_DOCKER_AUTH"] == "alice:tok"
