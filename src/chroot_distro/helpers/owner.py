# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Resolve a `--chown USER[:GROUP]` spec into the numeric pair chown(2) takes.

The names are looked up on the side the files land on, because the same name
answers to a different number on each: a container destination is asked of its
own `/etc/passwd` and `/etc/group`, a host destination of the host's. That is
the whole point of the flag: without it a transfer carries the source's numbers
across, which name whoever happens to hold them on the other side.

A number is accepted anywhere a name is and taken as it stands, so an id with no
entry to its name, which an image-installed rootfs is full of, is still
reachable. What cannot be guessed at is a *group* for a bare number, since there
is no entry to read a primary group from; that is refused naming the spelling
that works rather than silently using the uid as the gid.

Guest content is guest content: every field read out of a rootfs is checked for
being a number before it is used, so a `/etc/passwd` line saying `uid=root`
fails the lookup instead of the transfer.
"""

import grp
import pwd

from chroot_distro.commands.login.passwd import (
    find_passwd_by_uid,
    read_group_gid,
    read_passwd_field,
)
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.paths import container_from_spec, container_rootfs

_UID_MAX = 0xFFFFFFFE


def _as_id(text: str) -> int | None:
    """*text* as an id if it is written as one, else None."""
    if not text.isdigit():
        return None
    value = int(text)
    return value if value <= _UID_MAX else None


def _unknown(kind: str, name: str, where: str) -> ChrootDistroError:
    return ChrootDistroError(f"--chown: unknown {kind} '{name}' on {where}.")


def _host_user(user: str) -> tuple[int, int | None]:
    numeric = _as_id(user)
    if numeric is not None:
        try:
            return numeric, pwd.getpwuid(numeric).pw_gid
        except (KeyError, OverflowError, ValueError):
            return numeric, None
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        raise _unknown("user", user, "this host") from None
    return entry.pw_uid, entry.pw_gid


def _host_group(group: str) -> int:
    numeric = _as_id(group)
    if numeric is not None:
        return numeric
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise _unknown("group", group, "this host") from None


def _guest_user(rootfs: str, container: str, user: str) -> tuple[int, int | None]:
    numeric = _as_id(user)
    if numeric is not None:
        return numeric, _as_id(find_passwd_by_uid(rootfs, str(numeric))[2])
    uid = _as_id(read_passwd_field(rootfs, user, 2))
    if uid is None:
        raise _unknown("user", user, f"container '{container}'")
    return uid, _as_id(read_passwd_field(rootfs, user, 3))


def _guest_group(rootfs: str, container: str, group: str) -> int:
    numeric = _as_id(group)
    if numeric is not None:
        return numeric
    gid = _as_id(read_group_gid(rootfs, group))
    if gid is None:
        raise _unknown("group", group, f"container '{container}'")
    return gid


def resolve_owner(spec: str, dest_spec: str) -> tuple[int, int]:
    """Turn `USER`, `USER:GROUP` or `:GROUP` into (uid, gid) for *dest_spec*.

    With no group named (`arif` or `arif:`) the user's primary group stands
    in, which is what chown(1) does with the same spellings. With no user named
    (`:staff`) the group alone is changed and the uid comes back as -1, which
    chown(2) reads as "leave this one alone".
    """
    user, sep, group = spec.partition(":")
    if not user and not (sep and group):
        raise ChrootDistroError(
            "--chown needs a user or a group, as in '--chown arif', '--chown arif:staff' or '--chown :staff'."
        )

    container = container_from_spec(dest_spec)
    if container is not None:
        rootfs = container_rootfs(container)
        uid, primary = _guest_user(rootfs, container, user) if user else (-1, None)
        gid = _guest_group(rootfs, container, group) if group else primary
    else:
        uid, primary = _host_user(user) if user else (-1, None)
        gid = _host_group(group) if group else primary

    if gid is None:
        raise ChrootDistroError(
            f"--chown: no passwd entry for '{user}' to take a group from; name one, as in '--chown {user}:{user}'."
        )
    return uid, gid
