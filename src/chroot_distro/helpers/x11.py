"""Resolve host X11 display environment for chroot sessions."""

from __future__ import annotations

import contextlib
import glob
import os
import pwd
import shutil
import subprocess

GUEST_XAUTHORITY_PATH = "/var/tmp/.chroot-distro-xauthority"


def resolve_invoking_uid() -> int:
    """Return the UID of the user who invoked chroot-distro (not root via sudo)."""
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        return int(sudo_uid)
    return os.getuid()


_INVOKING_ENV_CACHE: dict[str, str] | None = None


def _get_ppid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read()
        rpar = stat.rfind(")")
        if rpar == -1:
            return None
        fields = stat[rpar + 2:].split()
        return int(fields[1])
    except Exception:
        return None


def get_invoking_env() -> dict[str, str]:
    """Walk up process tree to find first process owned by invoking UID, return its env."""
    global _INVOKING_ENV_CACHE
    if _INVOKING_ENV_CACHE is not None:
        return _INVOKING_ENV_CACHE

    invoking_uid = resolve_invoking_uid()
    pid = os.getpid()
    while pid and pid > 1:
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
            if uid == invoking_uid:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    content = f.read()
                env = {}
                for line in content.split(b"\0"):
                    if b"=" in line:
                        k, v = line.split(b"=", 1)
                        env[k.decode("utf-8", errors="replace")] = v.decode("utf-8", errors="replace")
                _INVOKING_ENV_CACHE = env
                return env
        except Exception:
            pass
        pid = _get_ppid(pid)
    _INVOKING_ENV_CACHE = {}
    return {}


def get_host_env_var(var: str, fallback: str = "") -> str:
    """Get env var from current environment, or invoking shell's environment if running under sudo."""
    val = os.environ.get(var, "")
    if val:
        return val
    invoking_env = get_invoking_env()
    return invoking_env.get(var, "") or fallback


def _invoking_home(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_dir
    except (KeyError, OSError):
        return None


def _is_safe_auth_path(path: str, uid: int, home: str | None) -> bool:
    """Allow only auth files under the invoking user's home or runtime dir."""
    real = os.path.realpath(path)
    runtime = f"/run/user/{uid}"
    if real.startswith(runtime + os.sep) or real == runtime:
        return True
    if home:
        home_real = os.path.realpath(home)
        if real.startswith(home_real + os.sep) or real == home_real:
            return True
    return False


def _discover_runtime_xauthority(uid: int) -> str | None:
    """Find Xwayland auth files under /run/user/<uid> when XAUTHORITY is unset."""
    runtime = f"/run/user/{uid}"
    if not os.path.isdir(runtime):
        return None
    candidates: list[str] = []
    for pattern in (
        ".mutter-Xwaylandauth.*",
        ".X11-Xwaylandauth.*",
        "xauth_*",
        ".xauth*",
    ):
        candidates.extend(glob.glob(os.path.join(runtime, pattern)))
    files = [path for path in candidates if os.path.isfile(path)]
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def resolve_host_x11_env() -> tuple[dict[str, str], list[str]]:
    """Return X11 env vars and host paths that must be bind-mounted for auth.

    Collects DISPLAY, XAUTHORITY, and XDG_RUNTIME_DIR from the host session,
    filling gaps when running under sudo without ``-E``.
    """
    uid = resolve_invoking_uid()
    home = _invoking_home(uid)
    runtime = f"/run/user/{uid}"

    env: dict[str, str] = {}
    bind_paths: list[str] = []

    for var in ("DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"):
        val = get_host_env_var(var)
        if val:
            env[var] = val

    if "DISPLAY" not in env:
        env["DISPLAY"] = ":0"

    if "XDG_RUNTIME_DIR" not in env and os.path.isdir(runtime):
        env["XDG_RUNTIME_DIR"] = runtime

    if "XAUTHORITY" not in env and home:
        fallback = os.path.join(home, ".Xauthority")
        if os.path.isfile(fallback):
            env["XAUTHORITY"] = fallback

    if "XAUTHORITY" not in env:
        discovered = _discover_runtime_xauthority(uid)
        if discovered:
            env["XAUTHORITY"] = discovered

    xauthority = env.get("XAUTHORITY", "")
    if xauthority and os.path.isfile(xauthority) and _is_safe_auth_path(xauthority, uid, home):
        real = os.path.realpath(xauthority)
        if real.startswith(runtime + os.sep) or real == runtime:
            # /run is already bind-mounted by default; ensure runtime dir is set.
            if "XDG_RUNTIME_DIR" not in env and os.path.isdir(runtime):
                env["XDG_RUNTIME_DIR"] = runtime
        elif real not in bind_paths:
            bind_paths.append(real)

    return env, bind_paths


def guest_can_read_auth(guest_uid: int, path: str) -> bool:
    """Return True if the guest UID can read the host X authority file."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    mode = st.st_mode & 0o777
    if st.st_uid == guest_uid:
        return True
    return bool(mode & 0o004)


def x11_auth_bind_path(xauthority: str) -> str | None:
    """Return a host path to bind-mount for *xauthority*, or None if unnecessary."""
    if not xauthority or not os.path.isfile(xauthority):
        return None
    uid = resolve_invoking_uid()
    home = _invoking_home(uid)
    if not _is_safe_auth_path(xauthority, uid, home):
        return None
    real = os.path.realpath(xauthority)
    runtime = f"/run/user/{uid}"
    if real.startswith(runtime + os.sep) or real == runtime:
        return None
    return real


def _display_names(display: str) -> list[str]:
    """Return display names to try with xauth, most specific first."""
    names: list[str] = []
    if display:
        names.append(display)
        if display.startswith(":"):
            names.append(f"unix{display}")
            names.append(f"unix/{display.lstrip(':')}")
    return names


def provision_guest_xauthority(
    rootfs: str,
    *,
    host_xauthority: str,
    display: str,
    guest_uid: int,
    guest_gid: int,
) -> str | None:
    """Copy the host display cookie into the rootfs for an unprivileged guest UID.

    chroot-distro runs as root on the host and can read the session cookie even
    when the guest UID cannot.  The copy lives under ``/var/tmp`` (not bind-mounted).
    """
    if not display or not host_xauthority or not os.path.isfile(host_xauthority):
        return None
    if shutil.which("xauth") is None:
        return None

    guest_host_path = os.path.join(rootfs, GUEST_XAUTHORITY_PATH.lstrip("/"))
    try:
        os.makedirs(os.path.dirname(guest_host_path), exist_ok=True)
    except OSError:
        return None

    with contextlib.suppress(OSError):
        os.remove(guest_host_path)

    for name in _display_names(display):
        try:
            result = subprocess.run(
                ["xauth", "-f", host_xauthority, "extract", guest_host_path, name],
                capture_output=True,
                check=False,
            )
        except OSError:
            return None
        if result.returncode == 0 and os.path.isfile(guest_host_path):
            try:
                os.chown(guest_host_path, guest_uid, guest_gid)
                os.chmod(guest_host_path, 0o600)
            except OSError:
                with contextlib.suppress(OSError):
                    os.remove(guest_host_path)
                return None
            return GUEST_XAUTHORITY_PATH
        with contextlib.suppress(OSError):
            os.remove(guest_host_path)

    return None
