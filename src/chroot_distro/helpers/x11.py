# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The host X11 session, recovered from under sudo, and a cookie the guest can read.

Two problems shape this file. The first is that the program self-elevates, so by
the time it runs, `DISPLAY` and `XAUTHORITY` are whatever root has, which is
usually nothing: `resolve_invoking_uid` takes `SUDO_UID` over the current uid,
and `get_invoking_env` walks up `/proc/<pid>` to the first process owned by that
uid and reads its `environ`, cached for the run. Every lookup here goes through
`get_host_env_var`, so the current environment wins and the recovered one only
fills gaps.

The second is that root can read an auth file the guest uid cannot, so handing
the guest a bind of the host cookie is not enough.
`provision_guest_xauthority` copies only the entries matching this display into
`GUEST_XAUTHORITY_PATH` inside the rootfs, chowned to the guest uid and chmod
0600. Guest parent symlinks resolve inside a pinned rootfs, then writes use the
parent descriptor and an exclusive atomic temporary. Failures before publication
preserve an old complete cookie. The path is under `/var/tmp` deliberately:
nothing binds over it by default.

An auth path is bound or copied only when `_is_safe_auth_path` accepts its
canonical form under the invoking user's home or `/run/user/<uid>`, since the
value arrives from another process's environment. Copying walks that same
canonical source without following links and reads the opened regular file.
A file already inside the runtime dir needs no bind of its own, because that
directory is bound as a whole.
`_discover_runtime_xauthority` covers a Wayland session that sets no `XAUTHORITY`
at all, taking the newest of the Xwayland auth files the compositors write there.
"""

from __future__ import annotations

import contextlib
import glob
import logging
import os
import pwd

from chroot_distro import dirfd
from chroot_distro.helpers.tar_extract import safe_resolve_parts_at
from chroot_distro.helpers.xauthority import match_display, read_xauthority, write_xauthority

log = logging.getLogger(__name__)

GUEST_XAUTHORITY_PATH = "/var/tmp/.chroot-distro-xauthority"


def resolve_invoking_uid() -> int:
    """Return the UID of the user who invoked chroot-distro (not root via sudo)."""
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        return int(sudo_uid)
    return os.getuid()


class _EnvCache:
    """Module-level cache for invoking environment."""

    value: dict[str, str] | None = None


def _get_ppid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat = f.read()
        rpar = stat.rfind(")")
        if rpar == -1:
            return None
        fields = stat[rpar + 2 :].split()
        return int(fields[1])
    except Exception:
        return None


def get_invoking_env() -> dict[str, str]:
    """Walk up process tree to find first process owned by invoking UID, return its env."""
    if _EnvCache.value is not None:
        return _EnvCache.value

    invoking_uid = resolve_invoking_uid()
    pid: int | None = os.getpid()
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
                _EnvCache.value = env
                return env
        except Exception as exc:
            log.debug("Failed to read environment from process %s: %s", pid, exc)
        pid = _get_ppid(pid)
    _EnvCache.value = {}
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
    """Check an already-canonical auth path against the user's home/runtime dir."""
    runtime = f"/run/user/{uid}"
    if path.startswith(runtime + os.sep) or path == runtime:
        return True
    if home:
        home_real = os.path.realpath(home)
        if path.startswith(home_real + os.sep) or path == home_real:
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
    real = os.path.realpath(xauthority) if xauthority else ""
    if real and os.path.isfile(real) and _is_safe_auth_path(real, uid, home):
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
    real = os.path.realpath(xauthority)
    if not _is_safe_auth_path(real, uid, home):
        return None
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
    if not display or not host_xauthority:
        return None

    try:
        source = os.path.realpath(host_xauthority)
        uid = resolve_invoking_uid()
        if not _is_safe_auth_path(source, uid, _invoking_home(uid)):
            return None
        with contextlib.ExitStack() as stack:
            host_fd = dirfd.opendir(os.sep)
            stack.callback(os.close, host_fd)
            source_parts = source.lstrip(os.sep).split(os.sep)
            source_parent = dirfd.descend_at(host_fd, source_parts[:-1])
            stack.callback(os.close, source_parent)
            source_fd, _ = dirfd.open_regular_at(source_parent, source_parts[-1], os.O_RDONLY)
            entries = read_xauthority(source_fd)
            for name in _display_names(display):
                matched = [entry for entry in entries if match_display(entry, name)]
                if matched:
                    break
            else:
                return None
            root_fd = dirfd.opendir(rootfs)
            stack.callback(os.close, root_fd)
            guest_parts = GUEST_XAUTHORITY_PATH.split("/")
            parent_parts = safe_resolve_parts_at(root_fd, guest_parts[:-1])
            if parent_parts is None:
                return None
            parent_fd = dirfd.descend_at(root_fd, parent_parts, create=True)
            stack.callback(os.close, parent_fd)
            write_xauthority(guest_parts[-1], matched, dir_fd=parent_fd, owner=(guest_uid, guest_gid))
    except (OSError, ValueError):
        return None
    return GUEST_XAUTHORITY_PATH
