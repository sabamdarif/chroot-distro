# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Group-gated privileged daemon and its client.

The access model is Docker's: a root-owned Unix socket at `/run/chroot-distro.sock`
whose group ownership (`chroot-distro`) decides who may run privileged commands,
with no password prompt and no sudoers change. `commands/setup.py` creates the
group and installs the service.

The socket is the trust boundary, so what a peer says about itself is never
believed. Its uid and gid come from the kernel through SO_PEERCRED, and
authorisation is root, or membership of the group by primary gid, member list or
supplementary groups. Everything else in a request is the peer's own text: the
header is read under `_HEADER_LIMIT`, and of the environment it offers only `CD_*`
names and `_CLIENT_ENV_ALLOWLIST` are passed on, because the child is about to
exec as root with whatever is handed to it. Display and session variables are on
that allowlist deliberately: the child sits in a different process tree from the
user's shell, so `helpers.x11.get_invoking_env()` cannot reach the real environment
and `--shared-display` would otherwise not work over the socket. For the same
reason `SUDO_UID`/`SUDO_USER` are set from the peer's uid, or
`resolve_invoking_uid()` answers with root's and the display helpers look in
/run/user/0, which does not exist.

The server forks per request and re-execs the CLI as root on the client's own
stdio, which arrives over the socket via SCM_RIGHTS, so an interactive `login`
works with no pty of the daemon's own. The client relays terminal signals
(`_RELAY_SIGNALS` plus SIGWINCH) to that child and exits with the code the server
reports.

Under systemd the listening socket is passed in by activation (`LISTEN_FDS`).
Under OpenRC, runit, dinit or sysvinit the daemon binds it itself and, unless
started with `--persist`, exits after `IDLE_TIMEOUT_SECONDS` idle.
"""

import contextlib
import grp
import json
import logging
import os
import pwd
import signal
import socket
import struct
import sys
import threading
import time

from chroot_distro.constants import DEFAULT_PATH_ENV
from chroot_distro.exceptions import ChrootDistroError

log = logging.getLogger(__name__)

SOCKET_PATH = "/run/chroot-distro.sock"
GROUP_NAME = "chroot-distro"
IDLE_TIMEOUT_SECONDS = 300.0
_ACCEPT_POLL_SECONDS = 30.0
_HEADER_LIMIT = 1024 * 1024

# Non-CD_* environment variables the client may forward to the root side.
# Display/session/audio vars are included so that --shared-display works
# when the tool is elevated through the daemon socket (the daemon's child
# process is in a different process tree from the user's shell, so the
# get_invoking_env() walk cannot reach the user's environment).
_CLIENT_ENV_ALLOWLIST = (
    "TERM",
    "LANG",
    "COLUMNS",
    "LINES",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "PULSE_SERVER",
    "DBUS_SESSION_BUS_ADDRESS",
)

# Terminal signals the client relays to the root-side child.
_RELAY_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
_RELAYABLE_SIGNAL_NUMBERS = {int(s) for s in _RELAY_SIGNALS} | {int(signal.SIGWINCH)}


def _client_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k.startswith("CD_") or k in _CLIENT_ENV_ALLOWLIST}


def run_client(argv: list[str]) -> int | None:
    """Delegate *argv* to the root daemon.

    Returns the command's exit code, or ``None`` when the daemon is not
    available / the caller is not authorised (so the caller can fall back
    to another elevation mechanism).
    """
    if os.environ.get("CD_NO_DAEMON") == "1":
        return None
    if not os.path.exists(SOCKET_PATH):
        return None
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.connect(SOCKET_PATH)
    except OSError:
        conn.close()
        return None

    header = json.dumps({"argv": argv, "cwd": os.getcwd(), "env": _client_env()}).encode()
    try:
        socket.send_fds(conn, [header], [0, 1, 2])
    except OSError:
        conn.close()
        return None

    def _relay(signum: int, _frame: object) -> None:
        with contextlib.suppress(OSError):
            conn.sendall(json.dumps({"signal": signum}).encode() + b"\n")

    previous_handlers = {}
    for sig in _RELAY_SIGNALS:
        with contextlib.suppress(OSError, ValueError):
            previous_handlers[sig] = signal.signal(sig, _relay)

    try:
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except InterruptedError:
                continue
            except OSError:
                return 1
            if not data:
                return 1
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    reply = json.loads(line)
                except ValueError:
                    return 1
                if "error" in reply:
                    # Not authorised (or malformed request): print the
                    # daemon's hint and let the caller fall back.
                    print(f"chroot-distro: {reply['error']}", file=sys.stderr)
                    return None
                if "exit" in reply:
                    return int(reply["exit"])
    finally:
        for sig, handler in previous_handlers.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, handler)
        conn.close()


def _activation_socket() -> socket.socket | None:
    """Return the listening socket handed over by systemd, if any."""
    if os.environ.get("LISTEN_FDS") == "1" and os.environ.get("LISTEN_PID") == str(os.getpid()):
        return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=3)
    return None


def _bind_socket() -> socket.socket:
    """Create and own the Unix socket: root:chroot-distro, mode 0660."""
    try:
        gid = grp.getgrnam(GROUP_NAME).gr_gid
    except KeyError as exc:
        raise ChrootDistroError(f"group '{GROUP_NAME}' does not exist. Run 'sudo chroot-distro setup' first.") from exc
    with contextlib.suppress(FileNotFoundError):
        os.unlink(SOCKET_PATH)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, gid)
    # Group-writable (0o660, root:chroot-distro) is the authorisation model:
    # only root and chroot-distro group members may connect. Peer identity is
    # further enforced via SO_PEERCRED in _peer_is_authorised.
    os.chmod(SOCKET_PATH, 0o660)  # lgtm[py/overly-permissive-file]
    sock.listen(16)
    return sock


def _peer_is_authorised(conn: socket.socket) -> tuple[bool, int]:
    """Check SO_PEERCRED against root / the chroot-distro group."""
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, gid = struct.unpack("3i", creds)
    if uid == 0:
        return True, uid
    try:
        group = grp.getgrnam(GROUP_NAME)
    except KeyError:
        return False, uid
    if gid == group.gr_gid:
        return True, uid
    try:
        user = pwd.getpwuid(uid)
    except KeyError:
        return False, uid
    if user.pw_name in group.gr_mem:
        return True, uid
    try:
        return group.gr_gid in os.getgrouplist(user.pw_name, user.pw_gid), uid
    except OSError:
        return False, uid


def _send_json(conn: socket.socket, payload: dict) -> None:
    with contextlib.suppress(OSError):
        conn.sendall(json.dumps(payload).encode() + b"\n")


def _spawn(header: dict, fds: list[int], *, peer_uid: int = 0) -> int:
    """Fork and exec the CLI as root on the client's file descriptors."""
    pid = os.fork()
    if pid != 0:
        return pid
    # --- child ---
    try:
        for target, fd in enumerate(fds[:3]):
            os.dup2(fd, target)
        for fd in fds:
            if fd > 2:
                os.close(fd)
        env = {
            "PATH": DEFAULT_PATH_ENV,
            "HOME": "/root",
            "_CHROOT_DISTRO_ELEVATING": "1",
            "_CHROOT_DISTRO_DAEMON": "1",
        }
        # resolve_invoking_uid() has to answer with the real user's uid, not
        # root's, or the display helpers look in /run/user/0, which does not exist.
        if peer_uid > 0:
            env["SUDO_UID"] = str(peer_uid)
            with contextlib.suppress(KeyError, OSError):
                env["SUDO_USER"] = pwd.getpwuid(peer_uid).pw_name
        for key, value in header.get("env", {}).items():
            if key.startswith("CD_") or key in _CLIENT_ENV_ALLOWLIST:
                env[key] = str(value)
        try:
            os.chdir(header.get("cwd") or "/")
        except OSError:
            os.chdir("/")
        argv = [sys.executable, "-m", "chroot_distro", *header["argv"]]
        os.execve(sys.executable, argv, env)
    finally:
        os._exit(127)


def _wait_and_relay(conn: socket.socket, pid: int) -> int:
    """Wait for the child while relaying client signals to it."""
    conn.settimeout(0.25)
    buf = b""
    while True:
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return 1
        if done == pid:
            code = os.waitstatus_to_exitcode(status)
            return 128 - code if code < 0 else code
        try:
            chunk = conn.recv(4096)
        except TimeoutError:
            continue
        except OSError:
            chunk = b""
        if chunk == b"":
            # Client disconnected: tear the command down.
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGHUP)
            try:
                _done, status = os.waitpid(pid, 0)
                code = os.waitstatus_to_exitcode(status)
                return 128 - code if code < 0 else code
            except ChildProcessError:
                return 1
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                signum = int(request.get("signal", 0))
            except (ValueError, TypeError):
                continue
            if signum in _RELAYABLE_SIGNAL_NUMBERS:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signum)


def _handle_connection(conn: socket.socket) -> None:
    try:
        allowed, uid = _peer_is_authorised(conn)
        try:
            data, fds, _flags, _addr = socket.recv_fds(conn, _HEADER_LIMIT, 8)
        except OSError:
            return
        try:
            header = json.loads(data.decode())
        except (ValueError, UnicodeDecodeError):
            header = None
        if not allowed:
            for fd in fds:
                os.close(fd)
            log.warning("rejected connection from uid %d (not in '%s' group)", uid, GROUP_NAME)
            _send_json(
                conn,
                {
                    "error": (
                        f"permission denied: user (uid {uid}) is not in the '{GROUP_NAME}' group. "
                        f"Add it with: sudo usermod -aG {GROUP_NAME} <username>, then log out and back in."
                    )
                },
            )
            return
        if not isinstance(header, dict) or not isinstance(header.get("argv"), list) or len(fds) < 3:
            for fd in fds:
                os.close(fd)
            _send_json(conn, {"error": "malformed request"})
            return
        log.info("uid %d -> chroot-distro %s", uid, " ".join(map(str, header["argv"])))
        pid = _spawn(header, fds, peer_uid=uid)
        for fd in fds:
            os.close(fd)
        exit_code = _wait_and_relay(conn, pid)
        _send_json(conn, {"exit": exit_code})
    finally:
        conn.close()


def serve(persist: bool = False) -> None:
    """Run the daemon accept loop (must be root).

    Exits after ``IDLE_TIMEOUT_SECONDS`` of inactivity unless *persist*
    is True or the socket came from systemd activation (systemd will
    simply re-activate on the next connection).
    """
    if os.getuid() != 0:
        raise ChrootDistroError("the chroot-distro daemon must run as root.")

    sock = _activation_socket()
    activated = sock is not None
    if sock is None:
        sock = _bind_socket()
    sock.settimeout(_ACCEPT_POLL_SECONDS)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info("listening on %s (activated=%s, persist=%s)", SOCKET_PATH, activated, persist)

    last_activity = time.monotonic()
    try:
        while True:
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                if any(t.name == "connection-handler" for t in threading.enumerate()):
                    last_activity = time.monotonic()
                    continue
                if not persist and time.monotonic() - last_activity > IDLE_TIMEOUT_SECONDS:
                    log.info("idle for %.0fs, exiting", IDLE_TIMEOUT_SECONDS)
                    return
                continue
            except OSError:
                return
            last_activity = time.monotonic()
            threading.Thread(
                target=_handle_connection,
                args=(conn,),
                name="connection-handler",
                daemon=True,
            ).start()
    finally:
        sock.close()
        if not activated:
            with contextlib.suppress(OSError):
                os.unlink(SOCKET_PATH)
