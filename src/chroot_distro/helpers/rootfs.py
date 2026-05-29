import contextlib
import grp
import os
import pwd
import stat

from chroot_distro.constants import (
    DEFAULT_PRIMARY_NS,
    DEFAULT_SECONDARY_NS,
)


def write_resolv_conf(rootfs: str) -> None:
    """Replace /etc/resolv.conf with a plain file containing default DNS servers."""
    path = os.path.join(rootfs, "etc", "resolv.conf")
    with contextlib.suppress(OSError):
        os.remove(path)
    with open(path, "w") as fh:
        fh.write(f"nameserver {DEFAULT_PRIMARY_NS}\n")
        fh.write(f"nameserver {DEFAULT_SECONDARY_NS}\n")


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
            fh.write(
                f"aid_{username_result}:x:{uid}:{gid}:Termux:/:/sbin/nologin\n"
            )
        with open(shadow_path, "a") as fh:
            fh.write(f"aid_{username_result}:*:18446:0:99999:7:::\n")
    except OSError:
        pass

    seen: set[int] = set()
    all_gids: list[int] = []
    for g in [gid, *os.getgroups()]:
        if g not in seen:
            seen.add(g)
            all_gids.append(g)

    for g in all_gids:
        try:
            gname = grp.getgrgid(g).gr_name
        except KeyError:
            continue
        try:
            with open(group_path, "a") as fh:
                fh.write(
                    f"aid_{gname}:x:{g}:root,aid_{username_result}\n"
                )
            if os.path.exists(gshadow_path):
                with open(gshadow_path, "a") as fh:
                    fh.write(
                        f"aid_{gname}:*::root,aid_{username_result}\n"
                    )
        except OSError:
            pass
