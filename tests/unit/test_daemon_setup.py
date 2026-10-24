import os
from unittest.mock import patch

import pytest

from chroot_distro.commands import setup as setup_mod
from chroot_distro.daemon import _spawn, run_client
from chroot_distro.exceptions import ChrootDistroError


def _realpath(path):
    return os.path.realpath(path)


def test_run_client_falls_back_when_cwd_is_deleted():
    """A deleted cwd must not turn the daemon path into an exception; '/' is the fallback."""
    header = {}

    def fake_send_fds(_conn, buffers, _fds):
        import json

        header.update(json.loads(buffers[0].decode()))
        return len(buffers[0])

    with (
        patch("chroot_distro.daemon.os.path.exists", return_value=True),
        patch("chroot_distro.daemon.socket.socket") as sock_cls,
        patch("chroot_distro.daemon.socket.send_fds", side_effect=fake_send_fds),
        patch("chroot_distro.daemon.os.getcwd", side_effect=OSError("No such file or directory")),
    ):
        # recv returns b"" immediately: server gone, run_client reports
        # delegation failed. The header has already been captured.
        sock_cls.return_value.recv.return_value = b""
        result = run_client(["login", "alpine"])

    assert result == 1
    assert header["cwd"] == "/"


def test_spawn_reexecs_with_isolated_mode(tmp_path):
    """The daemon's root child must not put the client's cwd on sys.path."""
    recorded = tmp_path / "argv"

    def fake_execve(executable, argv, env):
        recorded.write_text("\n".join(argv))
        os._exit(0)

    with (
        patch("chroot_distro.daemon.os.chdir", return_value=None),
        patch("chroot_distro.daemon.os.execve", side_effect=fake_execve),
    ):
        pid = _spawn({"argv": ["login", "alpine"], "cwd": str(tmp_path)}, [0, 1, 2], peer_uid=1000)
        _done, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0

    argv = recorded.read_text().splitlines()
    assert "-I" in argv
    assert "-m" in argv
    assert "chroot_distro" in argv


def test_systemd_unit_carries_a_capability_bounding_set():
    import re

    assert re.search(r"^CapabilityBoundingSet=@CAPS@$", setup_mod._SYSTEMD_SERVICE, re.MULTILINE)
    caps = set(setup_mod._DAEMON_CAPABILITIES)
    for required in (
        "CAP_SYS_ADMIN",
        "CAP_SYS_CHROOT",
        "CAP_SETUID",
        "CAP_SETGID",
        "CAP_MKNOD",
        "CAP_DAC_OVERRIDE",
        "CAP_CHOWN",
        "CAP_KILL",
        "CAP_SETPCAP",
        "CAP_SYS_PTRACE",
    ):
        assert required in caps


def test_systemd_unit_excludes_caps_containers_never_need():
    caps = set(setup_mod._DAEMON_CAPABILITIES)
    for dangerous in ("CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_BOOT", "CAP_SYS_TIME", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE"):
        assert dangerous not in caps


def test_capability_list_matches_the_guest_keep_set():
    """The unit's bounding set is inherited by containers, so it must cover every kept cap."""
    from chroot_distro.syscalls.capabilities import _CAP_NAMES, CAPS_TO_KEEP

    names = {_CAP_NAMES[cap] for cap in CAPS_TO_KEEP}
    assert names <= set(setup_mod._DAEMON_CAPABILITIES)


def test_install_service_replaces_both_placeholders():
    written = {}

    def fake_write(path, content, mode=0o644):
        written[path] = content

    with (
        patch("chroot_distro.commands.setup._write", side_effect=fake_write),
        patch("chroot_distro.commands.setup._run_quiet", return_value=True),
    ):
        setup_mod._install_service("systemd")

    service = written[setup_mod._SYSTEMD_SERVICE_PATH]
    assert "@CMD@" not in service
    assert "@CAPS@" not in service
    assert "CAP_SYS_ADMIN" in service


def test_setup_refuses_user_writable_interpreter(tmp_path, monkeypatch):
    """A root-owned package under a user-owned venv must still fail setup."""
    monkeypatch.setattr(setup_mod.os, "getuid", lambda: 0)
    monkeypatch.setattr(setup_mod, "IS_TERMUX", False)

    package_dir = tmp_path / "root-owned" / "chroot_distro"
    package_dir.mkdir(parents=True)
    interpreter_dir = tmp_path / "venv" / "bin"
    interpreter_dir.mkdir(parents=True)
    interpreter = interpreter_dir / "python3"
    interpreter.write_text("#!/bin/sh\n")
    interpreter.chmod(0o755)

    def fake_writable_by_non_root(path):
        if _realpath(path) == _realpath(str(interpreter)):
            return str(interpreter_dir)
        return None

    monkeypatch.setattr(setup_mod, "_package_dir", lambda: str(package_dir))
    monkeypatch.setattr(setup_mod, "_writable_by_non_root", fake_writable_by_non_root)
    monkeypatch.setattr(setup_mod.sys, "executable", str(interpreter))

    with pytest.raises(ChrootDistroError, match="Python interpreter"):
        setup_mod.command_setup(object())


def test_setup_allows_root_owned_everything(tmp_path, monkeypatch):
    """Sanity: the guard passes when neither package nor interpreter is user-writable."""
    monkeypatch.setattr(setup_mod.os, "getuid", lambda: 0)
    monkeypatch.setattr(setup_mod, "IS_TERMUX", False)
    monkeypatch.setattr(setup_mod, "_package_dir", lambda: str(tmp_path))
    monkeypatch.setattr(setup_mod, "_writable_by_non_root", lambda _path: None)
    monkeypatch.setattr(setup_mod.sys, "executable", "/usr/bin/python3")

    called = []

    class _Args:
        uninstall = False
        setup_user = None

    monkeypatch.setattr(setup_mod, "_ensure_group", lambda: called.append("group"))
    monkeypatch.setattr(setup_mod, "_detect_init", lambda: "sysvinit")
    monkeypatch.setattr(setup_mod, "_install_service", lambda _init: called.append("service"))
    monkeypatch.setattr(setup_mod, "_invoking_user", lambda _explicit: "arif")
    monkeypatch.setattr(setup_mod, "_add_user_to_group", lambda _user: None)
    monkeypatch.setattr(setup_mod.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(setup_mod.time, "sleep", lambda _seconds: None)

    setup_mod.command_setup(_Args())

    assert called == ["group", "service"]
