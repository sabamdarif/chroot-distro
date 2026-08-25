# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Resolve a user or group name against the rootfs's own /etc/passwd and /etc/group.

Never the host's databases: a USER line or a `--chown` spec names an identity
that exists in the image, and `pwd.getpwnam` would answer with whatever the host
happens to have under that name.

Both files are image content, and so is every directory component leading to
them, so the walk follows the path the way the guest sees it: one descriptor per
level, an absolute symlink target re-anchored at the rootfs, `..` clamped there
the way a chroot clamps it, and the hop count bounded. Anything that is not a
regular file, or that leads out, reads as absent.

Nothing bounds how large an image's passwd file is, so the read is capped and a
line the cap cut in half is dropped rather than parsed.

Every failure falls back to the caller's default: uid 0 for a USER, and the
resolved uid for a group that was not named. A name this lookup cannot find
therefore builds as root rather than failing the build.
"""

import contextlib
import logging
import os
import stat
import typing

from chroot_distro import dirfd

log = logging.getLogger(__name__)

# Same budget paths._resolve_within_root and tar_extract._safe_resolve use.
_MAX_SYMLINK_HOPS = 40

# Nothing bounds how large an image's passwd or group file is, and the whole
# point of reading it is that it was not written by us. A megabyte is thousands
# of entries; past that the file is not a passwd file, and reading it (or one
# arbitrarily long line of it) into memory is how a build gets killed rather
# than failed.
_MAX_ID_FILE_BYTES = 1 << 20


def _open_guest_file(rootfs_dir: str, guest_path: str, root_fd: int | None = None) -> typing.IO[str] | None:
    """Open the absolute guest path *guest_path* under *rootfs_dir*.

    Returns a text-mode file object for a regular file, or None when the path
    does not exist, names something other than a regular file, or leads out of
    the rootfs. Undecodable bytes are replaced rather than raised: the content
    is the image's, and a UnicodeDecodeError is not an OSError, so no caller's
    net would have caught one.

    Components are consumed one at a time off a directory descriptor, so the
    resolve and the open are a single walk with no window between them, and
    every hop is clamped: an absolute symlink target restarts at the rootfs
    (the guest's "/"), a relative one continues from the directory holding the
    link, and ".." stops at the rootfs the way a chroot does.

    *root_fd* is the rootfs when the caller has pinned it; the walk then
    starts from that inode instead of resolving the name again.
    """
    try:
        root_fd = dirfd.reopen(root_fd) if root_fd is not None else dirfd.opendir(rootfs_dir)
    except OSError:
        return None
    # One fd per level of the current path; ".." pops rather than opening a
    # name that would climb out of the rootfs.
    stack = [root_fd]
    pending = guest_path.split("/")
    hops = 0
    try:
        while pending:
            part = pending.pop(0)
            if part in ("", os.curdir):
                continue
            if part == os.pardir:
                if len(stack) > 1:
                    os.close(stack.pop())
                continue
            cur = stack[-1]
            try:
                st = dirfd.lstat_at(cur, part)
            except OSError:
                return None
            if stat.S_ISLNK(st.st_mode):
                hops += 1
                if hops > _MAX_SYMLINK_HOPS:
                    return None
                try:
                    target = os.readlink(part, dir_fd=cur)
                except OSError:
                    return None
                if target.startswith("/"):
                    while len(stack) > 1:
                        os.close(stack.pop())
                pending[:0] = target.split("/")
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    stack.append(dirfd.opendir_at(cur, part))
                except OSError:
                    return None
                continue
            if any(p not in ("", os.curdir) for p in pending):
                # A non-directory in the middle of the path.
                return None
            try:
                fd, _st = dirfd.open_regular_at(cur, part, os.O_RDONLY)
            except OSError:
                return None
            return open(fd, encoding="utf-8", errors="replace")
        # The path named a directory, not a file.
        return None
    finally:
        for fd in stack:
            with contextlib.suppress(OSError):
                os.close(fd)


def _read_capped(fh: typing.IO[str]) -> str:
    """Read at most _MAX_ID_FILE_BYTES, dropping a line the cap cut in half."""
    data = fh.read(_MAX_ID_FILE_BYTES + 1)
    if len(data) <= _MAX_ID_FILE_BYTES:
        return data
    data = data[:_MAX_ID_FILE_BYTES]
    return data[: data.rfind("\n") + 1]


def resolve_id(rootfs_dir: str, name: str, is_group: bool, default: int, *, root_fd: int | None = None) -> int:
    """Translate a user or group name into a numeric ID.

    Numeric strings pass through. Otherwise the name is looked up in
    the rootfs's own /etc/passwd or /etc/group (not the host's). Falls
    back to *default* on missing files or unknown names.
    """
    if not name:
        return default
    if name.isdigit():
        return int(name)
    guest_path = "/etc/group" if is_group else "/etc/passwd"
    fh = _open_guest_file(rootfs_dir, guest_path, root_fd)
    if fh is None:
        return default
    try:
        with fh:
            data = _read_capped(fh)
    except OSError as exc:
        log.debug("Failed to read user/group database at %s: %s", guest_path, exc)
        return default
    for line in data.splitlines():
        parts = line.split(":")
        if parts and parts[0] == name and len(parts) > 2:
            try:
                return int(parts[2])
            except ValueError:
                return default
    return default


def resolve_chown(rootfs_dir: str, chown: str, *, root_fd: int | None = None) -> tuple[int, int]:
    """Resolve --chown=user[:group] against the rootfs /etc/passwd."""
    if ":" in chown:
        user, group = chown.split(":", 1)
    else:
        user, group = chown, ""
    uid = resolve_id(rootfs_dir, user, is_group=False, default=0, root_fd=root_fd)
    gid = resolve_id(rootfs_dir, group, is_group=True, default=uid, root_fd=root_fd) if group else uid
    return uid, gid


def resolve_user_for_chroot(rootfs_dir: str, user_spec: str, *, root_fd: int | None = None) -> tuple[int, int]:
    """Resolve a USER directive's value into a (uid, gid) pair."""
    if not user_spec:
        return (0, 0)
    spec = str(user_spec).strip()
    if ":" in spec:
        u, g = spec.split(":", 1)
    else:
        u, g = spec, ""
    uid = resolve_id(rootfs_dir, u, is_group=False, default=0, root_fd=root_fd)
    gid = resolve_id(rootfs_dir, g, is_group=True, default=uid, root_fd=root_fd) if g else uid
    return uid, gid
