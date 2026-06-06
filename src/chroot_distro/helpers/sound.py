"""Resolve host audio (PulseAudio/PipeWire) environment for chroot sessions."""

from __future__ import annotations

import os

from chroot_distro.helpers.x11 import get_host_env_var, resolve_invoking_uid


def _runtime_dir(uid: int) -> str:
    """Return the XDG_RUNTIME_DIR path for *uid*."""
    return f"/run/user/{uid}"


def resolve_sound_env() -> dict[str, str]:
    """Return audio-related env vars collected from the host session.

    Resolved variables:
    - ``PULSE_SERVER``: from host ``$PULSE_SERVER``, fallback to
      ``unix:/run/user/<uid>/pulse/native`` if the socket exists.

    PipeWire does not need env vars — apps find the ``pipewire-0`` socket
    automatically via XDG_RUNTIME_DIR.  We only need to ensure
    XDG_RUNTIME_DIR is set (handled by display.py).
    """
    uid = resolve_invoking_uid()
    runtime = get_host_env_var("XDG_RUNTIME_DIR") or _runtime_dir(uid)
    env: dict[str, str] = {}

    # PulseAudio
    pulse_server = get_host_env_var("PULSE_SERVER")
    if pulse_server:
        env["PULSE_SERVER"] = pulse_server
    else:
        # Fallback: check for PulseAudio unix socket
        pulse_native = os.path.join(runtime, "pulse", "native")
        if os.path.exists(pulse_native):
            env["PULSE_SERVER"] = f"unix:{pulse_native}"

    return env
