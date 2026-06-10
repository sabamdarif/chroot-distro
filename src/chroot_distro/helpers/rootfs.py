import contextlib
import grp
import os
import pwd
import stat

from chroot_distro.constants import (
    DEFAULT_PRIMARY_NS,
    DEFAULT_SECONDARY_NS,
    IS_TERMUX,
    TERMUX_PREFIX,
)
from chroot_distro.helpers.android import termux_home_owner_ids

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

    # systemd-resolved stub (127.0.0.53) — read upstream servers instead.
    if "127.0.0.53" in content and os.path.isfile(_SYSTEMD_UPSTREAM_RESOLV):
        try:
            with open(_SYSTEMD_UPSTREAM_RESOLV) as fh:
                return _parse_nameservers(fh.read())
        except OSError:
            pass
    return []


def host_nameservers() -> list[str]:
    """Return DNS servers configured on the host, if any."""
    host_path = host_resolv_conf_path()
    if not host_path:
        return []
    return _read_resolv_nameservers(host_path)


def write_resolv_conf(rootfs: str) -> None:
    """Replace guest /etc/resolv.conf with a plain file using host DNS servers."""
    path = os.path.join(rootfs, "etc", "resolv.conf")
    servers = host_nameservers()
    if not servers:
        servers = [DEFAULT_PRIMARY_NS, DEFAULT_SECONDARY_NS]

    with contextlib.suppress(OSError):
        os.remove(path)
    with open(path, "w") as fh:
        for ns in servers:
            fh.write(f"nameserver {ns}\n")


def write_hosts(rootfs: str) -> None:
    """Write a minimal /etc/hosts into the rootfs."""
    path = os.path.join(rootfs, "etc", "hosts")
    with contextlib.suppress(OSError):
        os.remove(path)
    with open(path, "w") as fh:
        fh.write(
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


def register_android_ids(rootfs: str) -> None:
    """Add the Termux Android UID/GID entries to passwd/shadow/group/gshadow."""
    for p in ("etc/passwd", "etc/shadow", "etc/group", "etc/gshadow"):
        full = os.path.join(rootfs, p)
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

    passwd_path = os.path.join(rootfs, "etc", "passwd")
    shadow_path = os.path.join(rootfs, "etc", "shadow")
    group_path = os.path.join(rootfs, "etc", "group")
    gshadow_path = os.path.join(rootfs, "etc", "gshadow")

    try:
        with open(passwd_path, "a") as fh:
            fh.write(f"aid_{username_result}:x:{uid}:{gid}:Termux:/:/sbin/nologin\n")
        with open(shadow_path, "a") as fh:
            fh.write(f"aid_{username_result}:*:18446:0:99999:7:::\n")
    except OSError:
        pass

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
        except OSError:
            pass

    if os.path.exists(group_path) and "termux" not in existing_groups:
        try:
            with open(group_path, "a") as fh:
                fh.write(f"termux:x:{termux_gid}:\n")
            existing_groups.add("termux")
        except OSError:
            pass

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
        except OSError:
            pass

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
        except OSError:
            pass
