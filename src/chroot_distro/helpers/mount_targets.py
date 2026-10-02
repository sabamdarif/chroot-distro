# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Resolve a guest mount target to a descriptor, so a mount never follows a symlink.

A mount target is a guest path, and the rootfs is attacker-controlled in every
mode: a pulled layer, a local archive, a backup. mount(2) resolves a target
*path* through every symlink on it, so ``rootfs/proc -> /`` handed the fresh
procfs onto the host's own root. The walk here refuses that instead: each
component is opened O_NOFOLLOW off the descriptor of the one above, and the
mount is addressed to the leaf's descriptor as ``/proc/self/fd/<N>``, the shape
runc's mountViaFds uses. That is plain mount(2) with a name the kernel resolves
to a descriptor, so no new syscall and no new kernel version. The walk must
run in the namespace the mount lands in (a name on a tmpfs only that namespace
holds resolves nowhere else), so callers under a holder run these helpers
inside a setns'd child.

Two rules every caller relies on:

- A descriptor opened before a mount on the same leaf still names the mount it
  was opened on, so a remount or a mount stacked on top re-resolves the leaf.
- Mount *sources* are host paths this program chose, so they stay names; only
  the target side is untrusted. The one exception is the /dev/null a mask
  binds over a file: it is opened and inode-verified first, so nothing can be
  swapped in between.
"""

from __future__ import annotations

import contextlib
import logging
import os
import stat
from collections.abc import Sequence

from chroot_distro.exceptions import MountError, MountRefusedError
from chroot_distro.syscalls._constants import MS_BIND, MS_RDONLY, MS_REC
from chroot_distro.syscalls.mount import (
    _parse_and_split_mount_options,
    _parse_mount_options,
    fd_path,
    native_mount,
    remount_bind,
)

log = logging.getLogger(__name__)

O_PATH = getattr(os, "O_PATH", 0) or os.O_RDONLY


def guest_parts(rootfs: str, target: str) -> list[str]:
    """The guest components of host path *target* below *rootfs*.

    A target that is not inside *rootfs* is refused: the descriptor walk is
    what keeps a mount there, so a target that starts outside has nothing to
    walk. The caller has already resolved in-rootfs symlinks (the resolved
    path is symlink-free by construction), so what is left for the walk to
    catch is a component re-pointed after that resolution.
    """
    rel = os.path.relpath(os.path.abspath(target), os.path.abspath(rootfs))
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    if rel == os.pardir or rel.startswith(os.pardir + os.sep) or ".." in parts:
        raise MountRefusedError(f"mount target {target} is not inside rootfs {rootfs}")
    return parts


def resolve_mount_target(
    rootfs: str,
    parts: Sequence[str],
    *,
    want: str = "any",
    create: bool = True,
    created: list[list[str]] | None = None,
) -> int | None:
    """Open the mount target *parts* names under *rootfs*. Descriptor or None.

    Every component is opened O_NOFOLLOW off the descriptor of the one above,
    so a symlink anywhere on the path raises :class:`MountRefusedError`, and so
    does a plain file where a directory must be. Missing components are made
    when *create*: every level as a directory, plus the leaf as a regular file
    when *want* is ``"file"`` (a file bind needs a file to mount on); a leaf
    file made here is appended to *created* so the caller can roll it back.
    *want* is ``"dir"`` (the leaf must be a directory), ``"file"`` (a regular
    file) or ``"any"`` (whatever a bind can land on; a missing leaf is made
    as a file stub). A symlink leaf is always refused.

    None means the leaf is missing and *create* is false. A leaf file made
    here is appended to *created* as the parts of the made path, so the caller
    can roll it back. The caller owns the returned descriptor.
    """
    clean = [p for p in parts if p not in ("", ".")]
    if ".." in clean:
        raise MountRefusedError(f"invalid mount target /{'/'.join(parts)}")
    try:
        fd = os.open(rootfs, O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise MountError(f"cannot open rootfs {rootfs}: {exc}") from exc
    try:
        for i, part in enumerate(clean):
            leaf = i == len(clean) - 1
            flags = O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
            if not leaf or want == "dir":
                flags |= os.O_DIRECTORY
            try:
                nxt = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    return None
                if leaf and want != "dir":
                    # A non-directory bind (file, socket, device node) needs a
                    # non-directory to land on; a regular-file stub is that shape.
                    try:
                        stub = os.open(
                            part,
                            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o644,
                            dir_fd=fd,
                        )
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise MountRefusedError(f"cannot create mount target /{'/'.join(clean)}: {exc}") from exc
                    else:
                        os.close(stub)
                        if created is not None:
                            created.append(clean)
                else:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o777, dir_fd=fd)
                try:
                    nxt = os.open(part, flags, dir_fd=fd)
                except OSError as exc:
                    raise MountRefusedError(f"cannot create mount target /{'/'.join(clean)}: {exc}") from exc
            except OSError as exc:
                raise MountRefusedError(f"mount target /{'/'.join(clean)} refused at '{part}': {exc}") from exc
            os.close(fd)
            fd = nxt
        if clean and want != "dir":
            st = os.fstat(fd)
            if stat.S_ISLNK(st.st_mode):
                raise MountRefusedError(f"mount target /{'/'.join(clean)} is a symlink")
            if want == "file" and not stat.S_ISREG(st.st_mode):
                raise MountRefusedError(f"mount target /{'/'.join(clean)} is not a regular file")
        opened = fd
        fd = -1  # the caller owns it now; the finally must not close it
        return opened
    finally:
        if fd >= 0:
            os.close(fd)


def leaf_path(fd: int) -> str | None:
    """The canonical path of the inode *fd* names, or None.

    readlink on the procfs name for the descriptor answers where the walk
    landed without resolving any symlink by name, so the result is safe to
    hand to the code that reads and compares /proc/mounts entries.
    """
    try:
        return os.readlink(fd_path(fd))
    except OSError:
        return None


def unlink_mount_target(rootfs: str, parts: Sequence[str]) -> None:
    """Unlink the leaf *parts* names under *rootfs*, by descriptor. Best-effort.

    Rollback for a file stub this module made: the unlink is a second
    descriptor walk, so a name swapped in since the stub was created cannot
    redirect it onto another file. Nothing happens when the walk refuses.
    """
    clean = [p for p in parts if p not in ("", ".")]
    if not clean or ".." in clean:
        return
    parent = clean[:-1]
    leaf = clean[-1]
    try:
        fd = resolve_mount_target(rootfs, parent, want="dir", create=False)
    except (MountError, MountRefusedError):
        return
    if fd is None:
        return
    try:
        os.unlink(leaf, dir_fd=fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def bind_mount_fd(
    source: str,
    rootfs: str,
    parts: Sequence[str],
    *,
    want: str,
    recursive: bool = False,
    options: str = "",
    create: bool = True,
) -> None:
    """Bind *source* onto the target *parts* names under *rootfs*, by descriptor.

    *options* is the bind option string; its generic VFS tokens become
    per-mount flags on a remount pass, the way :func:`bind_mount` applies
    them. The leaf is re-resolved for that pass because a descriptor opened
    before the bind still names the mount it was opened on. A file stub this
    call created is removed again when the bind fails, so an empty
    placeholder cannot shadow a real rootfs entry.
    """
    clean = [p for p in parts if p not in ("", ".")]
    created: list[list[str]] = []
    fd = resolve_mount_target(rootfs, clean, want=want, create=create, created=created)
    if fd is None:
        raise MountError(f"mount target /{'/'.join(clean)} does not exist")
    bind_flags = MS_BIND | (MS_REC if recursive else 0)
    try:
        native_mount(source, fd_path(fd), None, bind_flags, None)
    except BaseException:
        # Roll a stub back the way it was made: a second descriptor walk, so
        # the unlink cannot be redirected by a name swapped in since.
        for made in created:
            unlink_mount_target(rootfs, made)
        raise
    finally:
        os.close(fd)
    extra_flags = _parse_mount_options(options)
    if not extra_flags:
        return
    # Re-resolve: the descriptor above now names the pre-bind mount.
    fd = resolve_mount_target(rootfs, clean, want=want, create=False)
    if fd is None:
        raise MountError(f"mount target /{'/'.join(clean)} does not exist")
    try:
        remount_bind(fd_path(fd), flags=extra_flags, recursive=recursive)
    finally:
        os.close(fd)


def mount_filesystem_fd(
    source: str,
    rootfs: str,
    parts: Sequence[str],
    fstype: str,
    *,
    flags: int = 0,
    options: str = "",
    create: bool = True,
) -> bool:
    """Mount *fstype* on the target *parts* names under *rootfs*, by descriptor.

    True when mounted. False means the target does not exist and *create* is
    false. The option string is split the way :func:`mount_filesystem` splits
    it, so generic VFS options become flags and the rest is data.
    """
    clean = [p for p in parts if p not in ("", ".")]
    fd = resolve_mount_target(rootfs, clean, want="dir", create=create)
    if fd is None:
        return False
    try:
        parsed_flags, data = _parse_and_split_mount_options(options, flags)
        native_mount(source, fd_path(fd), fstype, parsed_flags, data or None)
    finally:
        os.close(fd)
    return True


def mask_path(rootfs: str, parts: Sequence[str], *, is_dir: bool) -> bool:
    """Cover the *parts* entry under *rootfs*. True when masked.

    A file gets /dev/null bound over it, a directory a read-only tmpfs. The
    source is verified before binding, as runc does, and bound by name: a
    user namespace rejects an fd-path source. Best-effort: False means the
    target is missing (a mode whose filesystem does not carry the entry) or
    the mount was refused, and the caller skips it.
    """
    if is_dir:
        try:
            return mount_filesystem_fd(
                "tmpfs", rootfs, parts, "tmpfs", flags=0, options="ro,nosuid,nodev,noexec", create=False
            )
        except (MountError, OSError):
            return False
    want = "file" if len(parts) else "dir"
    try:
        fd = resolve_mount_target(rootfs, parts, want=want, create=False)
    except (MountError, MountRefusedError):
        return False
    if fd is None:
        return False
    try:
        # runc's own form: verify the /dev/null inode, then bind by name.
        null_fd = os.open("/dev/null", O_PATH | os.O_CLOEXEC)
        try:
            if not verify_dev_null(null_fd):
                return False
        finally:
            os.close(null_fd)
        native_mount("/dev/null", fd_path(fd), None, MS_BIND, None)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def readonly_path(rootfs: str, parts: Sequence[str]) -> bool:
    """Bind the *parts* entry under *rootfs* onto itself, read-only. True when done.

    The entry may be a directory or a file (`/proc/sysrq-trigger`). The
    self-bind by descriptor names the mount, and the remount re-resolves the
    leaf first (a descriptor opened before the bind still names the pre-bind
    mount). Best-effort like mask_path.
    """
    try:
        fd = resolve_mount_target(rootfs, parts, want="any", create=False)
    except (MountError, MountRefusedError):
        return False
    if fd is None:
        return False
    try:
        native_mount(fd_path(fd), fd_path(fd), None, MS_BIND, None)
    except OSError:
        return False
    finally:
        os.close(fd)
    try:
        fd = resolve_mount_target(rootfs, parts, want="any", create=False)
    except (MountError, MountRefusedError):
        return False
    if fd is None:
        return False
    try:
        remount_bind(fd_path(fd), flags=MS_RDONLY)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def verify_dev_null(fd: int) -> bool:
    """True when *fd* is the real char 1:3 device, not a planted stand-in."""
    try:
        st = os.fstat(fd)
    except OSError:
        return False
    return stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == 1 and os.minor(st.st_rdev) == 3


def verify_dev_node(fd: int, major: int, minor: int, *, char: bool = True) -> bool:
    """True when *fd* is the device node (type and major:minor) it claims to be.

    Used right after mknod, reopening the leaf O_NOFOLLOW, so an inode swapped
    in between is caught before any chmod touches it.
    """
    try:
        st = os.fstat(fd)
    except OSError:
        return False
    want = stat.S_IFCHR if char else stat.S_IFBLK
    return stat.S_IFMT(st.st_mode) == want and os.major(st.st_rdev) == major and os.minor(st.st_rdev) == minor



def open_ptmx(rootfs: str) -> int | None:
    """Open ``dev/pts/ptmx`` under *rootfs* and verify it. Descriptor or None.

    The node inside a devpts instance is char 5:2 and not a symlink, so
    anything else (an image's stand-in) is refused rather than pointed at by
    the ``/dev/ptmx`` symlink. The caller owns the returned descriptor.
    """
    try:
        dev_fd = resolve_mount_target(rootfs, ["dev"], want="dir", create=False)
    except MountError:
        return None
    if dev_fd is None:
        return None
    try:
        pts_fd = os.open("pts", O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dev_fd)
    except OSError:
        return None
    finally:
        os.close(dev_fd)
    try:
        fd = os.open("ptmx", O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=pts_fd)
    except OSError as exc:
        log.debug("ptmx at %s/dev/pts/ptmx not usable: %s", rootfs, exc)
        return None
    finally:
        os.close(pts_fd)
    if not verify_dev_node(fd, 5, 2):
        log.debug("ptmx at %s/dev/pts/ptmx is not the devpts multiplexer", rootfs)
        os.close(fd)
        return None
    return fd
