# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The Wayland half of a session's display environment.

`WAYLAND_DISPLAY` gets a `wayland-0` fallback only when that socket actually
exists in the runtime dir: naming a compositor that is not there would make a
toolkit try Wayland and fail instead of falling back to X11. The session
metadata (`XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`, `DESKTOP_SESSION`) is
forwarded with no fallback at all, since a guess there is a guess about the
host's desktop.

The host values come through `x11.get_host_env_var`, so a session sudo dropped
is still found. `display.py` merges the result.
"""

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

    wayland_display = get_host_env_var("WAYLAND_DISPLAY")
    if wayland_display:
        env["WAYLAND_DISPLAY"] = wayland_display
    else:
        if _wayland_socket_exists(runtime, "wayland-0"):
            env["WAYLAND_DISPLAY"] = "wayland-0"

    # Session metadata is forwarded from the host with no fallback.
    for var in ("XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"):
        val = get_host_env_var(var)
        if val:
            env[var] = val

    return env
