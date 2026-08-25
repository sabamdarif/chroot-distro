# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro setup`: the docker-group model, so no command asks for a password.

Run once as root on Linux: create the `chroot-distro` system group, add the
invoking user to it, install the daemon service for whichever init is running
(systemd socket activation, OpenRC, runit, dinit, sysvinit), and start it.
Membership takes effect at the next login, and `--uninstall` removes the service
while leaving the group. On Termux the command refuses: there is no root init
system to host a daemon, and reaching this point already triggered the one-time
`su` grant, so nothing is left to set up.

This file is the documented exception to the no-binary rule, and it is host
administration rather than container work: `groupadd`, `usermod` and the init
tools own state no syscall reaches. Each has a busybox spelling tried next and a
stdlib fallback last, editing `/etc/group` through a temporary that is chmod 0644
before the rename, because every process on the system resolves groups from that
file and one mode 0600 locks the host out of its own accounts.

`_writable_by_non_root` is the check that has to happen before anything is
written. The service re-executes this package as root, so a non-root owner or a
group or other write bit anywhere along the path to it turns the unit into a
local privilege escalation; the same walk catches a `pip install --user` tree,
which root's Python could not import at all.
"""

import argparse
import contextlib
import grp
import os
import pwd
import shutil
import subprocess
import sys
import time

import chroot_distro
from chroot_distro.constants import IS_TERMUX
from chroot_distro.daemon import GROUP_NAME, SOCKET_PATH
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.message import log_info, msg, warn

_DAEMON_CMD = f"{sys.executable} -m chroot_distro daemon"

_SUPPORTED_INITS = "systemd, OpenRC, runit, dinit, or sysvinit"

_SYSTEMD_SOCKET_PATH = "/etc/systemd/system/chroot-distro.socket"
_SYSTEMD_SERVICE_PATH = "/etc/systemd/system/chroot-distro.service"
_OPENRC_PATH = "/etc/init.d/chroot-distro"
_RUNIT_DIR = "/etc/sv/chroot-distro"
_DINIT_PATH = "/etc/dinit.d/chroot-distro"
_SYSV_PATH = "/etc/init.d/chroot-distro"

_SYSTEMD_SOCKET = f"""[Unit]
Description=chroot-distro privileged socket

[Socket]
ListenStream={SOCKET_PATH}
SocketMode=0660
SocketUser=root
SocketGroup={GROUP_NAME}

[Install]
WantedBy=sockets.target
"""

_SYSTEMD_SERVICE = """[Unit]
Description=chroot-distro privileged daemon
Requires=chroot-distro.socket

[Service]
Type=exec
ExecStart=@CMD@
Delegate=yes
"""

_OPENRC_SCRIPT = """#!/sbin/openrc-run

name="chroot-distro daemon"
description="Group-gated privileged daemon for chroot-distro"
command="@PYTHON@"
command_args="-m chroot_distro daemon --persist"
command_background="yes"
pidfile="/run/chroot-distro-daemon.pid"

depend() {
    need localmount
}
"""

_RUNIT_RUN = """#!/bin/sh
exec @CMD@ --persist
"""

_DINIT_SERVICE = """type = process
command = @CMD@ --persist
smooth-recovery = true
restart = true
"""

_SYSV_SCRIPT = """#!/bin/sh
### BEGIN INIT INFO
# Provides:          chroot-distro
# Required-Start:    $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: chroot-distro privileged daemon
### END INIT INFO

PIDFILE=/run/chroot-distro-daemon.pid

case "$1" in
  start)
    @CMD@ --persist &
    echo $! > "$PIDFILE"
    ;;
  stop)
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null; rm -f "$PIDFILE"
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
"""


def _free_system_gid() -> int:
    used = {g.gr_gid for g in grp.getgrall()}
    for gid in range(999, 99, -1):
        if gid not in used:
            return gid
    raise ChrootDistroError("no free system GID found for the chroot-distro group.")


def _ensure_group() -> None:
    try:
        grp.getgrnam(GROUP_NAME)
        return
    except KeyError:
        pass
    groupadd = shutil.which("groupadd")
    if groupadd:
        subprocess.run([groupadd, "--system", GROUP_NAME], check=True)
        return
    addgroup = shutil.which("addgroup")  # busybox
    if addgroup:
        subprocess.run([addgroup, "-S", GROUP_NAME], check=True)
        return
    with open("/etc/group", "a", encoding="utf-8") as fh:
        fh.write(f"{GROUP_NAME}:x:{_free_system_gid()}:\n")


def _add_user_to_group(username: str) -> None:
    group = grp.getgrnam(GROUP_NAME)
    if username in group.gr_mem:
        return
    usermod = shutil.which("usermod")
    if usermod:
        subprocess.run([usermod, "-aG", GROUP_NAME, username], check=True)
        return
    adduser = shutil.which("adduser")  # busybox
    if adduser:
        subprocess.run([adduser, username, GROUP_NAME], check=True)
        return
    # Last resort: edit /etc/group directly with the stdlib.
    with open("/etc/group", encoding="utf-8") as fh:
        lines = fh.readlines()
    for i, line in enumerate(lines):
        fields = line.rstrip("\n").split(":")
        if len(fields) >= 4 and fields[0] == GROUP_NAME:
            members = [m for m in fields[3].split(",") if m]
            if username not in members:
                members.append(username)
            fields[3] = ",".join(members)
            lines[i] = ":".join(fields) + "\n"
            break
    tmp_path = "/etc/group.chroot-distro.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    # /etc/group must stay world-readable; every process resolves groups here.
    os.chmod(tmp_path, 0o644)  # lgtm[py/overly-permissive-file]
    os.replace(tmp_path, "/etc/group")


def _package_dir() -> str:
    """Absolute directory the ``chroot_distro`` package is imported from."""
    return os.path.dirname(os.path.abspath(chroot_distro.__file__))


def _writable_by_non_root(path: str) -> str | None:
    """Return the first path component owned/writable by a non-root user.

    The daemon re-executes this package as root, so a non-root owner (or
    group/other write bit) anywhere along the path lets an unprivileged user
    replace the code root runs.
    """
    current = path
    while True:
        try:
            st = os.stat(current)
        except OSError:
            break
        if st.st_uid != 0 or (st.st_mode & 0o022):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _invoking_user(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for var in ("SUDO_USER", "DOAS_USER", "PKEXEC_UID", "LOGNAME", "USER"):
        value = os.environ.get(var)
        if not value:
            continue
        if var == "PKEXEC_UID":
            try:
                value = pwd.getpwuid(int(value)).pw_name
            except (ValueError, KeyError):
                continue
        if value != "root":
            return value
    return None


def _detect_init() -> str:
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if os.path.isdir("/run/openrc") or shutil.which("rc-update"):
        return "openrc"
    if shutil.which("dinitctl") and os.path.isdir("/etc/dinit.d"):
        return "dinit"
    if os.path.isdir("/etc/sv") and (shutil.which("sv") or shutil.which("runsvdir")):
        return "runit"
    if os.path.isdir("/etc/init.d"):
        return "sysvinit"
    return "unknown"


def _write(path: str, content: str, mode: int = 0o644) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    # 0o644 is correct for unit files, which init must read unprivileged;
    # callers needing an executable pass mode=0o755.
    os.chmod(path, mode)  # lgtm[py/overly-permissive-file]


def _run_quiet(argv: list[str]) -> bool:
    try:
        return subprocess.run(argv, capture_output=True, check=False).returncode == 0
    except OSError:
        return False


def _runit_service_dir() -> str | None:
    for candidate in ("/var/service", "/run/runit/service", "/etc/runit/runsvdir/default", "/service"):
        if os.path.isdir(candidate):
            return candidate
    return None


def _install_service(init: str) -> None:
    if init == "systemd":
        _write(_SYSTEMD_SOCKET_PATH, _SYSTEMD_SOCKET)
        _write(_SYSTEMD_SERVICE_PATH, _SYSTEMD_SERVICE.replace("@CMD@", _DAEMON_CMD))
        _run_quiet(["systemctl", "daemon-reload"])
        if not _run_quiet(["systemctl", "enable", "--now", "chroot-distro.socket"]):
            warn(
                "could not enable chroot-distro.socket; enable it manually with: systemctl enable --now chroot-distro.socket"
            )
    elif init == "openrc":
        _write(_OPENRC_PATH, _OPENRC_SCRIPT.replace("@PYTHON@", sys.executable), mode=0o755)
        _run_quiet(["rc-update", "add", "chroot-distro", "default"])
        if not _run_quiet(["rc-service", "chroot-distro", "start"]):
            warn("could not start the service; start it manually with: rc-service chroot-distro start")
    elif init == "runit":
        os.makedirs(_RUNIT_DIR, exist_ok=True)
        _write(os.path.join(_RUNIT_DIR, "run"), _RUNIT_RUN.replace("@CMD@", _DAEMON_CMD), mode=0o755)
        service_dir = _runit_service_dir()
        if service_dir:
            link = os.path.join(service_dir, "chroot-distro")
            if not os.path.islink(link) and not os.path.exists(link):
                os.symlink(_RUNIT_DIR, link)
        else:
            warn(f"runit service directory not found; link it manually: ln -s {_RUNIT_DIR} /var/service/")
    elif init == "dinit":
        _write(_DINIT_PATH, _DINIT_SERVICE.replace("@CMD@", _DAEMON_CMD))
        if not _run_quiet(["dinitctl", "enable", "chroot-distro"]):
            warn("could not enable the dinit service; enable it manually with: dinitctl enable chroot-distro")
    elif init == "sysvinit":
        _write(_SYSV_PATH, _SYSV_SCRIPT.replace("@CMD@", _DAEMON_CMD), mode=0o755)
        if shutil.which("update-rc.d"):
            _run_quiet(["update-rc.d", "chroot-distro", "defaults"])
        elif shutil.which("chkconfig"):
            _run_quiet(["chkconfig", "--add", "chroot-distro"])
        _run_quiet([_SYSV_PATH, "start"])
    else:
        warn("unknown init system: install a boot service yourself that runs (as root):")
        warn(f"  {_DAEMON_CMD} --persist")


def _uninstall_service() -> None:
    _run_quiet(["systemctl", "disable", "--now", "chroot-distro.socket", "chroot-distro.service"])
    _run_quiet(["rc-service", "chroot-distro", "stop"])
    _run_quiet(["rc-update", "del", "chroot-distro", "default"])
    _run_quiet(["dinitctl", "disable", "chroot-distro"])
    service_dir = _runit_service_dir()
    if service_dir:
        link = os.path.join(service_dir, "chroot-distro")
        if os.path.islink(link):
            os.unlink(link)
    for path in (
        _SYSTEMD_SOCKET_PATH,
        _SYSTEMD_SERVICE_PATH,
        _OPENRC_PATH,
        _DINIT_PATH,
        _SYSV_PATH,
        os.path.join(_RUNIT_DIR, "run"),
    ):
        with contextlib.suppress(OSError):
            os.unlink(path)
    with contextlib.suppress(OSError):
        os.rmdir(_RUNIT_DIR)
    with contextlib.suppress(OSError):
        os.unlink(SOCKET_PATH)
    _run_quiet(["systemctl", "daemon-reload"])


def command_setup(args: argparse.Namespace) -> None:
    if IS_TERMUX:
        # No root init system to host the daemon; Termux elevates via su.
        raise ChrootDistroError(
            "'chroot-distro setup' is meant only for a real Linux host running "
            f"one of: {_SUPPORTED_INITS}.\n"
            "On Termux there is no root init system: chroot-distro elevates via "
            "your root manager's 'su' (Magisk / KernelSU / APatch) directly, so "
            "no setup is required. Just run a command such as "
            "'chroot-distro install alpine' and approve the one-time su grant."
        )

    if os.getuid() != 0:
        raise ChrootDistroError("setup must run as root (it elevates automatically).")

    # Refuse before writing a service unit that would be a local privilege
    # escalation (or simply unimportable, for a `pip install --user` install).
    offender = _writable_by_non_root(_package_dir())
    if offender is not None:
        raise ChrootDistroError(
            "chroot-distro is installed in a location writable by a non-root "
            f"user:\n    {_package_dir()}\n"
            f"(offending path component: {offender})\n\n"
            "The root daemon re-executes this code as root, so it must be owned "
            "by root and not user-writable. A 'pip install --user' install also "
            "is not importable by root's Python, so the daemon would fail with "
            "'No module named chroot_distro'.\n\n"
            "Reinstall system-wide as root and re-run setup, for example:\n"
            "    sudo pip install chroot-distro\n"
            "    sudo chroot-distro setup"
        )

    if getattr(args, "uninstall", False):
        _uninstall_service()
        log_info("chroot-distro daemon service removed.")
        log_info(f"The '{GROUP_NAME}' group was kept; remove it with: groupdel {GROUP_NAME}")
        return

    _ensure_group()
    log_info(f"Group '{GROUP_NAME}' is present.")

    username = _invoking_user(getattr(args, "setup_user", None))
    if username:
        _add_user_to_group(username)
        log_info(f"User '{username}' added to the '{GROUP_NAME}' group.")
    else:
        warn(f"could not detect the invoking user; add yours manually: usermod -aG {GROUP_NAME} <username>")

    init = _detect_init()
    log_info(f"Detected init system: {init}")
    _install_service(init)

    for _ in range(15):
        if os.path.exists(SOCKET_PATH):
            break
        time.sleep(0.2)
    if os.path.exists(SOCKET_PATH):
        log_info(f"Daemon socket is live at {SOCKET_PATH}.")
    else:
        warn("daemon socket not up yet; it will be created when the service starts.")

    msg()
    log_info("Setup complete. Log out and back in (or run 'newgrp chroot-distro')")
    log_info("so your new group membership takes effect. After that, chroot-distro")
    log_info("commands run without any password prompt, like the docker group.")
