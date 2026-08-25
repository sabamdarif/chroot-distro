# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""One display environment for a session, and the host paths it needs bound.

`resolve_display_env` merges X11, Wayland, sound and D-Bus into a single dict,
first writer winning with X11 written first, so a variable a real X11 session
resolved is never overwritten by a Wayland or PulseAudio fallback. Nothing here
decides whether a passthrough is wanted; `login` asks for it.

`resolve_display_socket_binds` binds the invoking user's whole
`XDG_RUNTIME_DIR` (`/run/user/<uid>`) as one directory rather than the host
`/run`, which would expose NetworkManager, systemd-notify and every other
unrelated runtime socket, and rather than the individual socket files, which are
recreated by their servers and would leave a stale bind behind. The directory's
own ownership and modes come along, so the guest uid can traverse it, and the
caller binds it recursively with rslave so a socket created later still appears.

A D-Bus session socket living outside the runtime dir is added on its own, and
the system bus socket is bound at its real path with the usual `/var/run -> /run`
symlink resolved, so it lands at `/run/dbus/system_bus_socket` in the guest. Only
paths that exist are returned, runtime dir first so a nested fallback is bound
after the directory that contains it.
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


def _socket_from_pulse_server(pulse_server: str) -> str | None:
    """Extract a unix socket path from a PULSE_SERVER value, if any.

    Accepts forms like ``unix:/run/user/1000/pulse/native`` and
    ``unix:path=/run/user/1000/pulse/native``. Returns None for network
    (tcp:) servers or unparseable values.
    """
    if not pulse_server.startswith("unix:"):
        return None
    rest = pulse_server[len("unix:") :]
    if rest.startswith("path="):
        rest = rest[len("path=") :]
    rest = rest.split(",", 1)[0]
    return rest or None


def _socket_from_dbus_address(dbus_addr: str) -> str | None:
    """Extract a unix socket path from a DBUS_SESSION_BUS_ADDRESS value."""
    if "unix:path=" not in dbus_addr:
        return None
    after = dbus_addr.split("unix:path=", 1)[1]
    return after.split(",", 1)[0] or None


def resolve_display_socket_binds(env: dict[str, str]) -> list[str]:
    """Return host paths to bind for --shared-display.

    Rather than bind-mounting the whole host /run (which exposes
    NetworkManager, systemd-notify and other unrelated runtime sockets) OR
    binding fragile individual socket files, bind the user's whole
    XDG_RUNTIME_DIR (``/run/user/<uid>``) as a single directory. That
    preserves the host directory's ownership/permissions (so the guest UID
    can traverse it) and exposes every session socket the GUI needs
    (Wayland, PulseAudio, PipeWire, D-Bus) while still keeping the host's
    broad /run hidden. The caller binds this recursively with rslave so
    sockets created after mount stay visible.

    A D-Bus session socket that lives *outside* the runtime dir is added
    individually as a fallback. Only paths that exist are returned, runtime
    dir first so it is bound before any nested fallback.
    """
    uid = resolve_invoking_uid()
    runtime = env.get("XDG_RUNTIME_DIR") or get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)
    runtime = runtime.rstrip("/")

    binds: list[str] = []
    if os.path.isdir(runtime):
        binds.append(runtime)

    # D-Bus session socket outside the runtime dir (rare, but possible).
    dbus_addr = env.get("DBUS_SESSION_BUS_ADDRESS", "")
    dbus_socket = _socket_from_dbus_address(dbus_addr) if dbus_addr else None
    if dbus_socket and os.path.exists(dbus_socket):
        in_runtime = runtime and (dbus_socket == runtime or dbus_socket.startswith(runtime + os.sep))
        if not in_runtime and dbus_socket not in binds:
            binds.append(dbus_socket)

    # System D-Bus socket: lives outside the runtime dir at a well-known
    # path. Needed by apps/daemons that talk to system services (UPower,
    # notification daemons, NetworkManager, ...). Bind it at its host path
    # (resolving the common /var/run -> /run symlink) so it is reachable as
    # /run/dbus/system_bus_socket inside the container.
    for system_bus in ("/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"):
        if os.path.exists(system_bus):
            real = os.path.realpath(system_bus)
            if real not in binds:
                binds.append(real)
            break

    return binds


def resolve_display_env() -> tuple[dict[str, str], list[str]]:
    """Return all display/sound/dbus env vars and bind paths for auth files.

    Combines:
    - X11 env (DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR) + auth bind paths
    - Wayland env (WAYLAND_DISPLAY, XDG_SESSION_TYPE, XDG_CURRENT_DESKTOP, DESKTOP_SESSION)
    - Sound env (PULSE_SERVER)
    - D-Bus env (DBUS_SESSION_BUS_ADDRESS)

    Returns:
        (env_dict, bind_paths): env_dict maps var names to values,
        bind_paths lists host paths that must be bind-mounted for X11 auth.
    """
    env, bind_paths = resolve_host_x11_env()

    wayland_env = resolve_wayland_env()
    for key, val in wayland_env.items():
        if key not in env:
            env[key] = val

    sound_env = resolve_sound_env()
    for key, val in sound_env.items():
        if key not in env:
            env[key] = val

    dbus_env = _resolve_dbus_env()
    for key, val in dbus_env.items():
        if key not in env:
            env[key] = val

    return env, bind_paths
