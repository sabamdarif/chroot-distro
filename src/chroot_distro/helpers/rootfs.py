# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The guest `/etc` files this program writes, and the one safe way to reach them.

DNS and hosts are written at install time and patched at login, because a guest
resolving nothing is a guest that looks broken. `host_nameservers` skips the
loopback stubs (`127.0.0.53` and friends), which answer only for a daemon in the
host's network namespace, and reads systemd-resolved's upstream file instead;
with nothing usable found, the two public defaults from `constants` stand in.
`ensure_hosts_entry` adds the running hostname at login, which `sudo` and
anything else that reverse-resolves needs and which install time could not know.

Everything below the rootfs is image content, including `etc` itself, so both
writers go through `_open_etc` plus `_replace_at`: the directory is opened
`O_NOFOLLOW` off a pinned rootfs descriptor, an `etc` that is a symlink is
refused rather than followed (it would aim the write at a host directory, since
this runs outside the chroot), the old entry is unlinked instead of truncated so
a symlink under the name goes with it, and the create is `O_EXCL` so whatever
reappears under the name is not adopted. Mode comes from the descriptor, not the
umask, because the guest reads both files unprivileged.

`guest_etc_path` is the other half of that, for the files this module does not
own: it resolves a guest path *within* the rootfs, so an absolute symlink into
`/system/etc` (termux-docker ships `/etc/passwd` and `/etc/group` that way)
reaches the container's file instead of Android's read-only one.
`register_android_ids` is the install-time Termux fixup, adding the invoking
app's uid and its supplementary group ids to the four account files.
"""

import contextlib
import grp
import logging
import os
import pwd
import stat

from chroot_distro import dirfd
from chroot_distro.constants import (
    DEFAULT_PRIMARY_NS,
    DEFAULT_SECONDARY_NS,
    IS_TERMUX,
    TERMUX_PREFIX,
)
from chroot_distro.helpers.android import termux_home_owner_ids

log = logging.getLogger(__name__)

# Local stub resolvers that only work when the matching daemon runs in the
# same network namespace (e.g. systemd-resolved on the host).
_LOOPBACK_NAMESERVERS = frozenset({"127.0.0.1", "127.0.0.53", "::1", "0.0.0.0"})

_SYSTEMD_UPSTREAM_RESOLV = "/run/systemd/resolve/resolv.conf"


def host_resolv_conf_path() -> str | None:
    """Return the host path to resolv.conf, or None when unavailable."""
    path = os.path.join(TERMUX_PREFIX, "etc", "resolv.conf") if IS_TERMUX else "/etc/resolv.conf"
    if os.path.isfile(path) or os.path.islink(path):
        return path
    return None


def _parse_nameservers(content: str) -> list[str]:
    servers: list[str] = []
    seen: set[str] = set()
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            ns = parts[1]
            if ns in _LOOPBACK_NAMESERVERS or ns in seen:
                continue
            seen.add(ns)
            servers.append(ns)
    return servers


def _read_resolv_nameservers(path: str) -> list[str]:
    """Read usable nameserver entries from *path*, following symlinks."""
    try:
        real = os.path.realpath(path)
        with open(real) as fh:
            content = fh.read()
    except OSError:
        return []

    servers = _parse_nameservers(content)
    if servers:
        return servers

    # The systemd-resolved stub (127.0.0.53) is no use to a guest, so the
    # upstream servers are read instead.
    if "127.0.0.53" in content and os.path.isfile(_SYSTEMD_UPSTREAM_RESOLV):
        try:
            with open(_SYSTEMD_UPSTREAM_RESOLV) as fh:
                return _parse_nameservers(fh.read())
        except OSError as exc:
            log.debug("Failed to read systemd upstream resolv file: %s", exc)
    return []


def host_nameservers() -> list[str]:
    """Return DNS servers configured on the host, if any."""
    host_path = host_resolv_conf_path()
    if not host_path:
        return []
    return _read_resolv_nameservers(host_path)


def _open_etc(rootfs: str, root_fd: int | None) -> int | None:
    """Open <rootfs>/etc with O_NOFOLLOW, or None when there is none.

    `etc` is image content like everything below it: an image shipping it as
    a symlink aims both writers here at whatever directory the link names,
    and since they run outside the chroot that can be a host directory.
    None covers a missing `etc`, one that is a link, and one that is not a
    directory; every caller already treats the fixups as best-effort.

    *root_fd* is the rootfs when the caller has pinned it. `build` has one
    per stage, and the rootfs there is a name inside the build's scratch
    tree, which anything running as the invoking user can re-point,
    including a process a previous RUN step left behind.
    """
    own_fd = None
    try:
        if root_fd is None:
            own_fd = root_fd = dirfd.opendir(rootfs)
    except OSError:
        return None
    try:
        return dirfd.opendir_at(root_fd, "etc")
    except OSError:
        return None
    finally:
        if own_fd is not None:
            os.close(own_fd)


def _replace_at(etc_fd: int, name: str, content: str) -> None:
    """Replace <etc>/<name> with a plain file holding *content*.

    The mode is set on the descriptor rather than left to the umask, since
    the guest reads both files as an unprivileged user.

    The old entry is unlinked rather than truncated, so a symlink standing
    under the name is removed instead of written through, and the create is
    O_EXCL, so whatever reappears under the name is not adopted either (a
    hard link to a host file being the case nothing about the entry could
    reveal).
    """
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    dirfd.unlink_quietly(etc_fd, name)
    try:
        fd, _st = dirfd.open_new_at(etc_fd, name, mode)
    except OSError as exc:
        log.warning("Failed to write /etc/%s into the rootfs: %s", name, exc)
        return
    try:
        os.fchmod(fd, mode)
        os.write(fd, content.encode())
    except OSError as exc:
        log.warning("Failed to write /etc/%s into the rootfs: %s", name, exc)
    finally:
        os.close(fd)


def write_resolv_conf(rootfs: str, *, root_fd: int | None = None) -> None:
    """Replace guest /etc/resolv.conf with a plain file using host DNS servers."""
    servers = host_nameservers()
    if not servers:
        servers = [DEFAULT_PRIMARY_NS, DEFAULT_SECONDARY_NS]

    etc_fd = _open_etc(rootfs, root_fd)
    if etc_fd is None:
        return
    try:
        _replace_at(etc_fd, "resolv.conf", "".join(f"nameserver {ns}\n" for ns in servers))
    finally:
        os.close(etc_fd)


_HOSTS = (
    "# IPv4.\n"
    "127.0.0.1   localhost.localdomain localhost\n\n"
    "# IPv6.\n"
    "::1         localhost.localdomain localhost"
    " ip6-localhost ip6-loopback\n"
    "fe00::0     ip6-localnet\n"
    "ff00::0     ip6-mcastprefix\n"
    "ff02::1     ip6-allnodes\n"
    "ff02::2     ip6-allrouters\n"
    "ff02::3     ip6-allhosts\n"
)


def write_hosts(rootfs: str, *, root_fd: int | None = None) -> None:
    """Write a minimal /etc/hosts into the rootfs."""
    etc_fd = _open_etc(rootfs, root_fd)
    if etc_fd is None:
        return
    try:
        _replace_at(etc_fd, "hosts", _HOSTS)
    finally:
        os.close(etc_fd)


def ensure_hosts_entry(rootfs: str, *hostnames: str) -> None:
    """Ensure guest /etc/hosts maps each hostname to 127.0.0.1.

    sudo and other tools reverse-resolve the running hostname; without a
    matching /etc/hosts entry they fail with "unable to resolve host
    <name>". The relevant names are only known at login (the host kernel
    UTS name when not isolated, or the container name when isolated), after
    /etc/hosts was written at install time, so patch it here. Idempotent:
    a name already present on any line is left untouched. Best-effort.
    """
    path = os.path.join(rootfs, "etc", "hosts")
    try:
        with open(path) as fh:
            existing = fh.read()
    except OSError:
        return

    present = set()
    for line in existing.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        present.update(stripped.split()[1:])

    to_add = [h for h in dict.fromkeys(hostnames) if h and h not in present]
    if not to_add:
        return

    suffix = ("" if existing.endswith("\n") or not existing else "\n") + "".join(f"127.0.0.1   {h}\n" for h in to_add)
    with contextlib.suppress(OSError), open(path, "a") as fh:
        fh.write(suffix)


def guest_etc_path(rootfs: str, guest_path: str) -> str:
    """Resolve *guest_path* to its host location, keeping symlinks inside rootfs.

    Some images (e.g. termux-docker) ship /etc/passwd and /etc/group as
    symlinks with absolute targets such as /system/etc/passwd. Opening those
    directly from the host follows the symlink to the HOST's /system, which
    is read-only on Android (EROFS). Resolving within the rootfs redirects
    reads/writes to the container's own file instead.
    """
    from chroot_distro.commands.login.passwd import resolve_rootfs_path

    try:
        return resolve_rootfs_path(rootfs, guest_path)
    except OSError:
        return os.path.join(rootfs, guest_path.lstrip("/"))


def register_android_ids(rootfs: str) -> None:
    """Add the Termux Android UID/GID entries to passwd/shadow/group/gshadow."""
    for p in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"):
        full = guest_etc_path(rootfs, p)
        if os.path.exists(full):
            with contextlib.suppress(OSError):
                os.chmod(
                    full,
                    stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                )

    try:
        uid = os.getuid()
        gid = os.getgid()
        username_result = pwd.getpwuid(uid).pw_name
    except Exception:
        return

    passwd_path = guest_etc_path(rootfs, "/etc/passwd")
    shadow_path = guest_etc_path(rootfs, "/etc/shadow")
    group_path = guest_etc_path(rootfs, "/etc/group")
    gshadow_path = guest_etc_path(rootfs, "/etc/gshadow")

    try:
        with open(passwd_path, "a") as fh:
            fh.write(f"aid_{username_result}:x:{uid}:{gid}:Termux:/:/sbin/nologin\n")
        with open(shadow_path, "a") as fh:
            fh.write(f"aid_{username_result}:*:18446:0:99999:7:::\n")
    except OSError as exc:
        log.warning("Failed to write to passwd or shadow file in setup_android_permissions_legacy: %s", exc)

    try:
        _, termux_gid = termux_home_owner_ids()
    except OSError:
        termux_gid = gid

    seen: set[int] = set()
    all_gids: list[int] = []
    for g in [gid, *os.getgroups()]:
        if g not in seen:
            seen.add(g)
            all_gids.append(g)

    existing_groups: set[str] = set()
    if os.path.exists(group_path):
        try:
            with open(group_path) as fh:
                for line in fh:
                    parts = line.strip().split(":")
                    if parts and parts[0]:
                        existing_groups.add(parts[0])
        except OSError as exc:
            log.warning("Failed to read group file in setup_android_permissions_legacy: %s", exc)

    if os.path.exists(group_path) and "termux" not in existing_groups:
        try:
            with open(group_path, "a") as fh:
                fh.write(f"termux:x:{termux_gid}:\n")
            existing_groups.add("termux")
        except OSError as exc:
            log.warning("Failed to write to group file in setup_android_permissions_legacy: %s", exc)

    for g in all_gids:
        if g == termux_gid:
            continue
        try:
            gname = grp.getgrgid(g).gr_name
        except KeyError:
            continue
        aid_gname = f"aid_{gname}"
        if aid_gname in existing_groups:
            continue
        try:
            with open(group_path, "a") as fh:
                fh.write(f"{aid_gname}:x:{g}:root,aid_{username_result}\n")
            existing_groups.add(aid_gname)
            if os.path.exists(gshadow_path):
                with open(gshadow_path, "a") as fh:
                    fh.write(f"{aid_gname}:*::root,aid_{username_result}\n")
        except OSError as exc:
            log.warning("Failed to append to group or gshadow file in setup_android_permissions_legacy: %s", exc)

    # Ensure Android-specific groups exist in /etc/group
    android_groups = [
        ("aid_inet", "aid_inet:x:3003:"),
        ("aid_net_raw", "aid_net_raw:x:3004:"),
        ("aid_bluetooth", "aid_bluetooth:x:1002:"),
        ("aid_graphics", "aid_graphics:x:1003:"),
        ("aid_input", "aid_input:x:1004:"),
        ("aid_audio", "aid_audio:x:1005:"),
        ("aid_video", "aid_video:x:1006:"),
        ("aid_drm", "aid_drm:x:1007:"),
        ("aid_wifi", "aid_wifi:x:1010:"),
        ("aid_usb", "aid_usb:x:1018:"),
        ("aid_bt_admin", "aid_bt_admin:x:3001:"),
        ("aid_bt_net", "aid_bt_net:x:3002:"),
        ("aid_admin", "aid_admin:x:3005:"),
    ]

    if os.path.exists(group_path):
        try:
            with open(group_path, "a") as fh:
                for gname, gline in android_groups:
                    if gname not in existing_groups:
                        fh.write(gline + "\n")
                        existing_groups.add(gname)
        except OSError as exc:
            log.warning("Failed to write Android-specific groups in setup_android_permissions_legacy: %s", exc)
