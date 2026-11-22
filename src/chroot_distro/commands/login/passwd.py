# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The guest's own account databases, and the path resolver the login shares.

`resolve_rootfs_path` is the part that matters beyond this file. It resolves an
absolute guest path the way the guest would: each component followed inside the
rootfs, an absolute link target re-anchored at the rootfs, `..` collapsed so no
walk climbs above it, and a bounded hop count for a link loop. It answers with a
path, so it decides *where* something is and nothing more; where a hostile tree
could race that answer, the descriptor walk in `dirfd.py` is the tool, not this.

The databases read here are the image's, never the host's: a `--user` name, a
group, a home and a shell mean what the container's `/etc/passwd` and `/etc/group`
say they mean, and `pwd.getpwnam` would answer with whatever the host happens to
have under the same name. `resolve_host_home` is the deliberate exception, since
`--shared-home` needs a host directory to bind: it prefers the invoking account
(`SUDO_USER`, the real uid, `LOGNAME`) even for a root login, because the program
self-elevates through sudo and `$HOME` is `/root` by then.

Login can match a guest account to the owner of a shared home or its own home.
The caller pins the installed rootfs and holds the session lock while editing and
refreshing the identity. One atomic passwd replacement updates both the selected
account and any UID conflicts. Root is only repaired to 0:0. Password hashes
and aging data in /etc/shadow are independent of these IDs.
"""

import contextlib
import errno
import logging
import os

from chroot_distro import dirfd
from chroot_distro.helpers.rootfs import edit_guest_file
from chroot_distro.helpers.tar_extract import safe_resolve_parts_at

log = logging.getLogger(__name__)


def resolve_rootfs_path(rootfs: str, guest_path: str) -> str:
    """Resolve an absolute guest path to its real host path.

    Follows symlinks within the rootfs namespace, even if the final target
    of a symlink does not exist.
    """
    rootfs = os.path.abspath(rootfs)
    current_guest = "/"
    components = [c for c in guest_path.split("/") if c]

    symlink_count = 0
    max_symlinks = 40

    i = 0
    while i < len(components):
        comp = components[i]
        next_guest = os.path.normpath(os.path.join(current_guest, comp))
        host_path = os.path.join(rootfs, next_guest.lstrip("/"))

        try:
            is_link = os.path.islink(host_path)
        except OSError:
            is_link = False

        if is_link:
            symlink_count += 1
            if symlink_count > max_symlinks:
                raise OSError(errno.ELOOP, "Too many levels of symbolic links", guest_path)

            try:
                target = os.readlink(host_path)
            except OSError:
                current_guest = next_guest
                i += 1
                continue

            if os.path.isabs(target):
                target_components = [c for c in target.split("/") if c]
                components = target_components + components[i + 1 :]
                current_guest = "/"
                i = 0
            else:
                target_components = [c for c in target.split("/") if c]
                components = components[:i] + target_components + components[i + 1 :]
        else:
            current_guest = next_guest
            i += 1

    return os.path.join(rootfs, current_guest.lstrip("/"))


def read_passwd_field(rootfs: str, user: str, field_index: int) -> str:
    """Return a single colon-delimited field for *user* from /etc/passwd."""
    try:
        passwd = resolve_rootfs_path(rootfs, "/etc/passwd")
    except OSError:
        return ""
    try:
        with open(passwd) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if parts and parts[0] == user and len(parts) > field_index:
                    return parts[field_index]
    except OSError as exc:
        log.debug("Failed to read fields from /etc/passwd: %s", exc)
    return ""


def find_passwd_by_uid(rootfs: str, uid: str) -> tuple:
    """Return (home, shell, primary_gid) for the given UID, or ('','','')."""
    try:
        passwd = resolve_rootfs_path(rootfs, "/etc/passwd")
    except OSError:
        return ("", "", "")
    try:
        with open(passwd) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 7 and parts[2] == uid:
                    return (parts[5], parts[6], parts[3])
    except OSError as exc:
        log.debug("Failed to find passwd entry by UID: %s", exc)
    return ("", "", "")


def read_group_gid(rootfs: str, group: str) -> str:
    """Return the GID string for the named group from /etc/group, or ''."""
    try:
        group_file = resolve_rootfs_path(rootfs, "/etc/group")
    except OSError:
        return ""
    try:
        with open(group_file) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if parts and parts[0] == group and len(parts) > 2:
                    return parts[2]
    except OSError as exc:
        log.debug("Failed to read group GID from /etc/group: %s", exc)
    return ""


def set_passwd_uid_gid(
    root_fd: int,
    username: str,
    uid: int,
    gid: int,
    *,
    release_conflicts: bool = False,
) -> bool | None:
    """Report a committed ID change, or None if there is no usable account."""
    with edit_guest_file(root_fd, "/etc/passwd", same_mount=True) as fh:
        lines = fh.getvalue().split("\n")
        records = {}
        for index, line in enumerate(lines):
            fields = line.split(":")
            valid = len(fields) == 7 and bool(fields[0]) and "\0" not in line
            if fields[0] == username and not valid:
                return None
            if valid:
                records[index] = fields
        if not any(fields[0] == username for fields in records.values()):
            return None

        uid_s, gid_s = str(uid), str(gid)
        used_uids = {fields[2].lstrip("0") or "0" for fields in records.values()}
        used_uids.add(uid_s)
        candidate = 1001
        changed = False
        for index, fields in records.items():
            if fields[0] == username:
                new_ids = [uid_s, gid_s]
            elif release_conflicts and (fields[2].lstrip("0") or "0") == uid_s:
                if fields[0] == "root":
                    new_ids = ["0", "0"]
                else:
                    while str(candidate) in used_uids:
                        candidate += 1
                    new_ids = [str(candidate), str(candidate)]
                    candidate += 1
            else:
                continue

            if fields[2:4] != new_ids:
                fields[2:4] = new_ids
                lines[index] = ":".join(fields)
                changed = True
        if changed:
            fh.seek(0)
            fh.truncate()
            fh.write("\n".join(lines))
    return changed


def resolve_host_home(login_user: str | None = None) -> str | None:
    """Host path to bind for ``--shared-home``.

    Prefer the invoking account (``SUDO_USER``, real uid, ``LOGNAME``) for
    every login user, root included: chroot-distro self-elevates via sudo,
    which resets ``$HOME`` to ``/root``, so ``$HOME`` is only a last-resort
    fallback for root logins.
    """
    import pwd

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except (KeyError, OSError) as exc:
            log.debug("Failed to resolve home for sudo user '%s': %s", sudo_user, exc)

    if os.getuid() != 0:
        try:
            return pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError) as exc:
            log.debug("Failed to resolve home for current UID: %s", exc)

    for env_name in ("LOGNAME", "USER"):
        name = os.environ.get(env_name)
        if name and name != "root":
            try:
                return pwd.getpwnam(name).pw_dir
            except (KeyError, OSError):
                continue

    if not login_user or login_user == "root":
        return os.environ.get("HOME") or os.path.expanduser("~")

    try:
        return pwd.getpwnam(login_user).pw_dir
    except (KeyError, OSError) as exc:
        log.debug("Failed to resolve home for login user '%s': %s", login_user, exc)

    return None


def sync_passwd_to_home_owner(root_fd: int, username: str, guest_home: str) -> bool | None:
    """Match an account to a home directory on the installed rootfs mount."""
    if not guest_home or guest_home == "/" or "\0" in guest_home:
        return False
    parts = safe_resolve_parts_at(root_fd, guest_home.split("/"))
    if not parts:
        return False
    home_fd = dirfd.descend_at(root_fd, parts, same_mount=True)
    try:
        st = os.fstat(home_fd)
    finally:
        os.close(home_fd)

    if st.st_uid == 0:
        return False
    return set_passwd_uid_gid(root_fd, username, st.st_uid, st.st_gid, release_conflicts=True)


def reown_home_tree_for_uid(
    rootfs: str,
    guest_home: str,
    old_uid: int,
    new_uid: int,
    new_gid: int,
) -> None:
    """Reassign files in *guest_home* from *old_uid* to (*new_uid*, *new_gid*)."""
    if not guest_home or guest_home == "/":
        return
    try:
        home_path = resolve_rootfs_path(rootfs, guest_home)
    except OSError:
        return
    if not os.path.isdir(home_path):
        return

    def _maybe_reown(path: str) -> None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return
        if st.st_uid == old_uid:
            with contextlib.suppress(OSError):
                os.chown(path, new_uid, new_gid)

    for dirpath, dirnames, filenames in os.walk(home_path):
        _maybe_reown(dirpath)
        for name in dirnames + filenames:
            _maybe_reown(os.path.join(dirpath, name))


def find_user_groups(rootfs: str, username: str, primary_gid: str) -> list[str]:
    """Return a list of group GIDs that the user belongs to (primary + supplementary)."""
    gids = []
    if primary_gid:
        gids.append(primary_gid)

    try:
        group_file = resolve_rootfs_path(rootfs, "/etc/group")
    except OSError:
        return gids

    try:
        with open(group_file) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    gid = parts[2]
                    users = parts[3].split(",") if parts[3] else []
                    if username in users and gid not in gids:
                        gids.append(gid)
    except OSError as exc:
        log.debug("Failed to read group file to find user groups: %s", exc)
    return gids
