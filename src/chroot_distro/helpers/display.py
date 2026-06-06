"""Unified display environment resolver for chroot sessions.

Aggregates X11, Wayland, sound, and D-Bus env vars from the host
into a single interface used by the login command.
"""

from __future__ import annotations

import os

from chroot_distro.helpers.sound import resolve_sound_env
from chroot_distro.helpers.wayland import resolve_wayland_env
from chroot_distro.helpers.x11 import (
    get_host_env_var,
    resolve_host_x11_env,
    resolve_invoking_uid,
)


def _runtime_dir(uid: int) -> str:
    """Return the XDG_RUNTIME_DIR path for *uid*."""
    return f"/run/user/{uid}"


def _resolve_dbus_env() -> dict[str, str]:
    """Return D-Bus session bus env vars from the host.

    Resolved variables:
    - ``DBUS_SESSION_BUS_ADDRESS``: from host ``$DBUS_SESSION_BUS_ADDRESS``,
      fallback ``unix:path=/run/user/<uid>/bus`` if the socket exists.
    """
    uid = resolve_invoking_uid()
    runtime = get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)
    env: dict[str, str] = {}

    dbus_addr = get_host_env_var("DBUS_SESSION_BUS_ADDRESS")
    if dbus_addr:
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus_addr
    else:
        bus_socket = os.path.join(runtime, "bus")
        if os.path.exists(bus_socket):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_socket}"

    return env


def resolve_display_env() -> tuple[dict[str, str], list[str]]:
    """Return all display/sound/dbus env vars and bind paths for auth files.

    Combines:
    - X11 env (DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR) + auth bind paths
    - Wayland env (WAYLAND_DISPLAY, XDG_SESSION_TYPE, XDG_CURRENT_DESKTOP, DESKTOP_SESSION)
    - Sound env (PULSE_SERVER)
    - D-Bus env (DBUS_SESSION_BUS_ADDRESS)

    Returns:
        (env_dict, bind_paths) — env_dict maps var names to values,
        bind_paths lists host paths that must be bind-mounted for X11 auth.
    """
    # X11 (existing, returns env + bind paths)
    env, bind_paths = resolve_host_x11_env()

    # Wayland
    wayland_env = resolve_wayland_env()
    for key, val in wayland_env.items():
        if key not in env:
            env[key] = val

    # Sound
    sound_env = resolve_sound_env()
    for key, val in sound_env.items():
        if key not in env:
            env[key] = val

    # D-Bus
    dbus_env = _resolve_dbus_env()
    for key, val in dbus_env.items():
        if key not in env:
            env[key] = val

    return env, bind_paths
