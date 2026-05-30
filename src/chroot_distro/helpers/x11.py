"""Resolve host X11 display environment for chroot sessions."""

from __future__ import annotations

import os
import pwd


def resolve_invoking_uid() -> int:
    """Return the UID of the user who invoked chroot-distro (not root via sudo)."""
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        return int(sudo_uid)
    return os.getuid()


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
        val = os.environ.get(var, "")
        if val:
            env[var] = val

    if "XDG_RUNTIME_DIR" not in env and os.path.isdir(runtime):
        env["XDG_RUNTIME_DIR"] = runtime

    if "XAUTHORITY" not in env and home:
        fallback = os.path.join(home, ".Xauthority")
        if os.path.isfile(fallback):
            env["XAUTHORITY"] = fallback

    xauthority = env.get("XAUTHORITY", "")
    if xauthority and os.path.isfile(xauthority):
        if _is_safe_auth_path(xauthority, uid, home):
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
    if mode & 0o004:
        return True
    return False


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
