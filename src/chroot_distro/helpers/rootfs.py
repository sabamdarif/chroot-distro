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

Everything below the rootfs is image content, including `etc` itself, so the
install-time writers use `_open_etc` plus `_replace_at`: the directory is opened
`O_NOFOLLOW` off a pinned rootfs descriptor, an `etc` that is a symlink is
refused rather than followed (it would aim the write at a host directory, since
this runs outside the chroot), the old entry is unlinked instead of truncated so
a symlink under the name goes with it, and the create is `O_EXCL` so whatever
reappears under the name is not adopted. Mode comes from the descriptor, not the
umask, because the guest reads both files unprivileged.

`register_android_ids` is the install-time Termux fixup, adding the invoking
account and its supplementary group ids to the four account files. Android
fixups share `edit_guest_file`: guest symlinks resolve inside the pinned root,
parents are re-walked without following links, and regular files with one link
are read before fresh atomic replacement. Public accounts use mode 0644,
shadow files use 0600, and configuration files retain their permissions and
ownership. Missing parents and unsafe entries never fall back to host paths.
Login hostname insertion uses the same editor, retaining existing hosts content
and ordinary permissions while refusing shared inodes and special files.
Login account updates also require the opened parent and file to stay on the
pinned rootfs mount.
"""

import contextlib
import errno
import grp
import io
import logging
import os
import pwd
import stat
from collections.abc import Iterator

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.constants import (
    DEFAULT_PRIMARY_NS,
    DEFAULT_SECONDARY_NS,
    IS_TERMUX,
    TERMUX_PREFIX,
)
from chroot_distro.helpers.android import termux_home_owner_ids
from chroot_distro.helpers.tar_extract import safe_resolve_parts_at

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
    try:
        with contextlib.ExitStack() as stack:
            root_fd = dirfd.opendir(rootfs)
            stack.callback(os.close, root_fd)
            with edit_guest_file(root_fd, "/etc/hosts") as fh:
                existing = fh.getvalue()
                present = set()
                for line in existing.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    present.update(stripped.split()[1:])

                to_add = [h for h in dict.fromkeys(hostnames) if h and h not in present]
                if not to_add:
                    return

                if existing and not existing.endswith("\n"):
                    fh.write("\n")
                fh.write("".join(f"127.0.0.1   {h}\n" for h in to_add))
    except (OSError, UnicodeError):
        return


@contextlib.contextmanager
def edit_guest_file(
    root_fd: int,
    guest_path: str,
    *,
    create: bool = False,
    mode: int | None = None,
    same_mount: bool = False,
) -> Iterator[io.StringIO]:
    """Edit a guest file through a pinned parent, refusing shared inodes."""
    parts = safe_resolve_parts_at(root_fd, guest_path.split("/"))
    if not parts:
        raise OSError(errno.ELOOP, "guest file does not resolve to a leaf", guest_path)
    parent_fd = dirfd.descend_at(root_fd, parts[:-1], same_mount=same_mount)
    try:
        original = None
        content = ""
        try:
            fd, original = dirfd.open_regular_at(parent_fd, parts[-1], os.O_RDONLY, same_mount=same_mount)
        except FileNotFoundError:
            if not create:
                raise
        else:
            with os.fdopen(fd) as fh:
                if original.st_nlink != 1:
                    raise OSError(errno.EMLINK, "refusing a hardlinked guest file", guest_path)
                content = fh.read()
        permissions = mode if mode is not None else (stat.S_IMODE(original.st_mode) & 0o777 if original else 0o644)
        with io.StringIO() as buffer:
            buffer.write(content)
            yield buffer
            updated = buffer.getvalue()
        if original is None or updated != content or (mode is not None and stat.S_IMODE(original.st_mode) != mode):
            with atomic_write(parts[-1], dir_fd=parent_fd, mode=permissions) as out:
                if original is not None:
                    os.fchown(out.fileno(), original.st_uid, original.st_gid)
                out.write(updated)
    finally:
        os.close(parent_fd)


def _append_account_entries(root_fd: int, path: str, entries: list[str], *, create: bool, mode: int) -> None:
    with edit_guest_file(root_fd, path, create=create, mode=mode) as fh:
        existing = {line.split(":", 1)[0] for line in fh.getvalue().splitlines()}
        for entry in entries:
            name = entry.split(":", 1)[0]
            if name not in existing:
                if fh.getvalue() and not fh.getvalue().endswith("\n"):
                    fh.write("\n")
                fh.write(entry + "\n")
                existing.add(name)


def register_android_ids(rootfs: str, *, root_fd: int | None = None) -> None:
    """Add Android account entries on Termux, requiring an existing guest passwd."""
    if not IS_TERMUX:
        return
    try:
        uid = os.getuid()
        gid = os.getgid()
        username = pwd.getpwuid(uid).pw_name
    except (OSError, KeyError):
        return

    try:
        with contextlib.ExitStack() as stack:
            root_fd = dirfd.opendir(rootfs) if root_fd is None else os.dup(root_fd)
            stack.callback(os.close, root_fd)
            _append_account_entries(
                root_fd,
                "/etc/passwd",
                [f"aid_{username}:x:{uid}:{gid}:Termux:/:/sbin/nologin"],
                create=False,
                mode=0o644,
            )
            try:
                _, termux_gid = termux_home_owner_ids()
            except OSError:
                termux_gid = gid

            groups = [f"termux:x:{termux_gid}:"]
            gshadow = []
            for group_id in dict.fromkeys([gid, *os.getgroups()]):
                if group_id == termux_gid:
                    continue
                try:
                    name = grp.getgrgid(group_id).gr_name
                except KeyError:
                    continue
                groups.append(f"aid_{name}:x:{group_id}:root,aid_{username}")
                gshadow.append(f"aid_{name}:*::root,aid_{username}")

            from chroot_distro.helpers.android import ANDROID_GROUPS

            groups.extend(f"{name}:x:{group_id}:" for name, group_id in ANDROID_GROUPS.items())
            for path, entries, mode in (
                ("/etc/shadow", [f"aid_{username}:*:18446:0:99999:7:::"], 0o600),
                ("/etc/group", groups, 0o644),
                ("/etc/gshadow", gshadow, 0o600),
            ):
                try:
                    _append_account_entries(root_fd, path, entries, create=True, mode=mode)
                except (OSError, UnicodeError) as exc:
                    log.warning("Failed to register Android accounts in %s: %s", path, exc)
    except FileNotFoundError:
        return
    except (OSError, UnicodeError) as exc:
        log.warning("Failed to register Android accounts: %s", exc)
