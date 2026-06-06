"""Resolve host Wayland display environment for chroot sessions."""

from __future__ import annotations

import os

from chroot_distro.helpers.x11 import get_host_env_var, resolve_invoking_uid


def _runtime_dir(uid: int) -> str:
    """Return the XDG_RUNTIME_DIR path for *uid*."""
    return f"/run/user/{uid}"


def _wayland_socket_exists(runtime: str, name: str) -> bool:
    """Return True if a Wayland compositor socket exists in *runtime*."""
    return os.path.exists(os.path.join(runtime, name))


def resolve_wayland_env() -> dict[str, str]:
    """Return Wayland-related env vars collected from the host session.

    Resolved variables:
    - ``WAYLAND_DISPLAY``: from host ``$WAYLAND_DISPLAY``, fallback ``wayland-0``
      only if the socket actually exists in XDG_RUNTIME_DIR.
    - ``XDG_SESSION_TYPE``: forwarded from host (no fallback).
    - ``XDG_CURRENT_DESKTOP``: forwarded from host (no fallback).
    - ``DESKTOP_SESSION``: forwarded from host (no fallback).
    """
    uid = resolve_invoking_uid()
    runtime = get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)
    env: dict[str, str] = {}

    # Wayland display
    wayland_display = get_host_env_var("WAYLAND_DISPLAY")
    if wayland_display:
        env["WAYLAND_DISPLAY"] = wayland_display
    else:
        # Fallback: check if default wayland-0 socket exists
        if _wayland_socket_exists(runtime, "wayland-0"):
            env["WAYLAND_DISPLAY"] = "wayland-0"

    # Session metadata — forward from host, no fallback
    for var in ("XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"):
        val = get_host_env_var(var)
        if val:
            env[var] = val

    return env
