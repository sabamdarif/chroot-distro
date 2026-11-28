# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Extract a tar stream into a rootfs, member by member, safely.

One streaming extractor serves image layers, plain rootfs tarballs and backups.
Plain tarballs can drop leading components with `strip`. Backups require an exact
`rootfs_prefix` on members and hardlink targets before dropping it. When
`handle_whiteouts` is True, a first pass validates the archive and collects
whiteouts. Only after the whiteouts have been applied to the lower tree does
the second pass write this layer's entries.

An archive is a document this program did not write, so the loop filters before it
writes. Block, char and FIFO entries are skipped. A member is dropped when a
component after *strip* is empty or `..`, or when its last component is `.`, which
names the directory the member already sits in rather than an entry of its own;
interior `.` components stay, since OCI layers spell their paths `./foo` as a
matter of course. A whiteout's target, the name after `.wh.`, is held to the same
rule: `.wh...` spells `..`, which is the extraction root's own parent for a
whiteout at the top of a layer. `member.linkname` is filtered and resolved exactly
like `member.name`, or a crafted archive could name `../../etc/shadow` and have
the host's file copied into a destination it chose inside the rootfs.

Every destination's parent goes through `safe_resolve_parts`, which walks
pre-existing symlink components with each hop clamped inside the rootfs: an
absolute target re-roots at the rootfs, mirroring the guest's own view where `/`
is the rootfs, so a legitimate absolute symlink still lands in the right place,
and `..` can never ascend past it. Without this an earlier member shipping
`evil -> /` would have a later `evil/passwd` written through it onto the host.

Resolving says where a member *belongs*; it does not make writing there safe. It
decides by name, and a component re-pointed between the resolve and the write
sends the member wherever it then leads, which on Termux is an ordinary process's
reach: a container being installed lives under CONTAINERS_DIR, inside the prefix
bound read-write into every non-isolated container. The extraction therefore holds
a *descriptor* on the rootfs, re-walks each resolved parent off it with O_NOFOLLOW
(`dirfd.descend_at`) and names every entry as `(dir_fd, name)`. Regular files are
created O_EXCL (`dirfd.open_new_at`), which covers the one thing O_NOFOLLOW
cannot: a hardlink left under a member's name is indistinguishable from an
ordinary file, and a write through it would land on the inode it shares.

Hardlinks become independent copies in dependency order after the ordinary
members. A later entry at the same destination supersedes a pending copy.
Directories get at least S_IRWXU while children are written and receive their
mtimes after the last write. Parent descriptors are cached one deep
(`_Parents`). Progress counts compressed bytes consumed (`ByteCounter`).
"""

import contextlib
import os
import shutil
import stat
import sys
import typing
from collections.abc import Sequence
from itertools import dropwhile

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.helpers.tar_stream import open_tar
from chroot_distro.message import quote_path
from chroot_distro.progress import ByteCounter, clear_bar, draw_bytes_bar

_Parts = tuple[str, ...]


class _Hardlink(typing.NamedTuple):
    source: Sequence[str]
    uid: int
    gid: int
    offset: int


def extract_tar_to_rootfs(
    archive_path: str,
    rootfs_fd: int,
    *,
    strip: int = 0,
    handle_whiteouts: bool = False,
) -> None:
    """Stream-extract *archive_path* into the directory *rootfs_fd* names.

    The rootfs is a **descriptor**, not a path: every member is written as
    (dir_fd, name) beneath it, so the root is the inode the caller validated
    rather than a name it can be asked to resolve again, and nothing below it
    can be redirected by a component swapped since it was resolved. The caller
    owns the descriptor.

    See the module comment for the shared invariants. The function consumes a
    compressed-or-not tar stream via tarfile's `'r|*'` auto-detect, so it works
    for raw tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst and a Docker/OCI layer
    blob alike.
    """
    total_size = os.path.getsize(archive_path)
    with open(archive_path, "rb") as archive:
        extract_tar_stream(archive, total_size, rootfs_fd, strip=strip, handle_whiteouts=handle_whiteouts)


def extract_tar_stream(
    archive: typing.BinaryIO,
    total_size: int,
    rootfs_fd: int,
    *,
    strip: int = 0,
    rootfs_prefix: tuple[str, ...] = (),
    handle_whiteouts: bool = False,
) -> None:
    """Extract from an open archive at its start. The caller owns both descriptors."""
    deferred_links: dict[_Parts, _Hardlink] = {}
    deferred_dirs: dict[_Parts, tuple[float, int]] = {}
    removed_dirs: dict[_Parts, int] = {}
    parents = _Parents(rootfs_fd)

    try:
        if handle_whiteouts:
            offset = archive.tell()
            _apply_layer_whiteouts(archive, rootfs_fd, parents, strip, rootfs_prefix)
            archive.seek(offset)
        counter = ByteCounter(archive)
        with open_tar(counter) as tf:
            for member in tf:
                _process_member(
                    member,
                    tf,
                    rootfs_fd,
                    parents,
                    strip=strip,
                    rootfs_prefix=rootfs_prefix,
                    handle_whiteouts=handle_whiteouts,
                    deferred_links=deferred_links,
                    deferred_dirs=deferred_dirs,
                    removed_dirs=removed_dirs,
                )
                draw_bytes_bar(counter.count, total_size)

        pending = {
            dest: link
            for dest, link in deferred_links.items()
            if not _ancestor_removed(dest, link.offset, removed_dirs)
        }
        _finish_hardlinks(rootfs_fd, parents, pending)

        for parts, (mtime, offset) in deferred_dirs.items():
            if _ancestor_removed(parts, offset, removed_dirs):
                continue
            with contextlib.suppress(OSError):
                parent_fd = parents.get(parts[:-1], create=False)
                fd = dirfd.opendir_at(parent_fd, parts[-1])
                try:
                    os.utime(fd, (mtime, mtime))
                finally:
                    os.close(fd)
    finally:
        parents.close()
        clear_bar()


class _Parents:
    """One-deep cache of the descriptor a member's parent resolves to.

    Every entry is written as (dir_fd, name) off the directory the resolved
    components were re-walked to, and a tar lists its members in tree order, so
    consecutive entries nearly always share a parent. Holding the last one
    costs a single descriptor and saves the whole descent; a different parent
    closes it and walks again.

    The cache is keyed on the *components*, so a directory removed and remade
    between two members is never reused: any such member has a different parent
    (its own is one level up), which evicts the entry.
    """

    def __init__(self, root_fd: int) -> None:
        self._root_fd = root_fd
        self._key: tuple[str, ...] | None = None
        self._fd: int | None = None

    def get(self, parts: Sequence[str], *, create: bool = True) -> int:
        """The descriptor for *parts* under the root. Raises OSError."""
        key = tuple(parts)
        if self._fd is not None and self._key == key:
            return self._fd
        self.close()
        fd = dirfd.descend_at(self._root_fd, key, create=create)
        self._key, self._fd = key, fd
        return fd

    def close(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
            self._key = None


def _ancestor_removed(parts: _Parts, offset: int, removed_dirs: dict[_Parts, int]) -> bool:
    return any(removed_dirs.get(parts[:i], -1) > offset for i in range(1, len(parts)))


def _finish_hardlinks(rootfs_fd: int, parents: _Parents, pending: dict[_Parts, _Hardlink]) -> None:
    """Follow each chain before copying its members back from the source."""
    while pending:
        path = next(iter(pending))
        chain: dict[_Parts, _Parts] = {}
        while path in pending:
            if path in chain:
                raise tarfile.ReadError(f"cyclic tar hardlink at {quote_path('/'.join(path))}")
            link = pending[path]
            parent = safe_resolve_parts_at(rootfs_fd, link.source[:-1])
            if parent is None:
                raise tarfile.ReadError(f"unresolvable tar hardlink source: {quote_path('/'.join(link.source))}")
            source = (*parent, link.source[-1])
            if source not in pending:
                resolved = safe_resolve_parts_at(rootfs_fd, source)
                if not resolved:
                    raise tarfile.ReadError(f"unresolvable tar hardlink source: {quote_path('/'.join(link.source))}")
                source = tuple(resolved)
            chain[path] = source
            path = source

        for dest in reversed(chain):
            _copy_hardlink(rootfs_fd, parents, dest, chain[dest], pending.pop(dest))


def _copy_hardlink(rootfs_fd: int, parents: _Parents, dest: _Parts, source: _Parts, link: _Hardlink) -> None:
    """Copy a regular source through descriptors and apply the link's ownership."""
    try:
        src_fd = dirfd.descend_at(rootfs_fd, source[:-1])
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise tarfile.ReadError(f"missing tar hardlink source: {quote_path('/'.join(source))}") from exc
    try:
        try:
            source_st = dirfd.lstat_at(src_fd, source[-1])
        except FileNotFoundError as exc:
            raise tarfile.ReadError(f"missing tar hardlink source: {quote_path('/'.join(source))}") from exc
        if not stat.S_ISREG(source_st.st_mode) or source[:len(dest)] == dest:
            raise tarfile.ReadError(f"invalid tar hardlink source: {quote_path('/'.join(source))}")
        dst_fd = parents.get(dest[:-1], create=False)
        dirfd.rmtree_at(dst_fd, dest[-1], force=True)
        dirfd.copy_file_at(src_fd, source[-1], dst_fd, dest[-1], owner=(link.uid, link.gid))
    finally:
        os.close(src_fd)


def tar_path_parts(name: str) -> tuple[str, ...]:
    """Split an archive name after removing leading slashes and dot components."""
    name = name.strip("/")
    return tuple(dropwhile(lambda part: part == ".", name.split("/"))) if name else ()


def _relative_parts(name: str, strip: int, rootfs_prefix: tuple[str, ...]) -> Sequence[str]:
    if not rootfs_prefix:
        return name.strip("/").split("/")[strip:]

    parts = tar_path_parts(name)
    depth = len(rootfs_prefix)
    return parts[depth:] if parts[:depth] == rootfs_prefix else ()


def _member_parts(name: str, strip: int, rootfs_prefix: _Parts) -> _Parts:
    parts = _relative_parts(name, strip, rootfs_prefix)
    if not parts or parts[-1] == "." or any(part in ("..", "") for part in parts):
        return ()
    return tuple(part for part in parts if part != ".")


def _apply_layer_whiteouts(
    archive: typing.BinaryIO, rootfs_fd: int, parents: _Parents, strip: int, rootfs_prefix: _Parts
) -> None:
    """Resolve markers against the lower tree, skipping directory symlinks the layer replaces."""
    whiteouts: list[_Parts] = []
    upper_dirs: set[_Parts] = set()
    with open_tar(ByteCounter(archive)) as tf:
        for member in tf:
            parts = _member_parts(member.name, strip, rootfs_prefix)
            if not parts:
                continue
            if _is_whiteout(parts[-1]):
                if not member.isreg() or member.size:
                    raise tarfile.ReadError(f"tar whiteout must be an empty regular file: {quote_path(member.name)}")
                whiteouts.append(parts)
            elif member.isdir():
                upper_dirs.add(parts)

    if not whiteouts:
        return

    replaced: set[_Parts] = set()
    for parts in upper_dirs:
        parent = safe_resolve_parts_at(rootfs_fd, parts[:-1])
        if parent is not None:
            replaced.add((*parent, parts[-1]))

    targets = []
    for parts in whiteouts:
        parent = safe_resolve_parts_at(rootfs_fd, parts[:-1], replaced_dirs=replaced)
        if parent is not None:
            targets.append((parent, parts[-1]))

    for parent, name in targets:
        try:
            parent_fd = parents.get(parent, create=False)
        except (FileNotFoundError, NotADirectoryError):
            continue
        _apply_whiteout(parent_fd, name)


def _process_member(
    member, tf, rootfs_fd, parents, *, strip, rootfs_prefix, handle_whiteouts, deferred_links, deferred_dirs, removed_dirs
):
    if not (member.isdir() or member.issym() or member.islnk() or member.isreg()):
        return

    rel_parts = _member_parts(member.name, strip, rootfs_prefix)
    if not rel_parts or (handle_whiteouts and _is_whiteout(rel_parts[-1])):
        return

    parent_parts = safe_resolve_parts_at(rootfs_fd, rel_parts[:-1])
    if parent_parts is None:
        return
    name = rel_parts[-1]
    dest = (*parent_parts, name)
    link_parts = _member_parts(member.linkname, strip, rootfs_prefix) if member.islnk() else ()
    if member.islnk() and not link_parts:
        return

    parent_fd = parents.get(parent_parts)
    deferred_links.pop(dest, None)
    try:
        existing = dirfd.lstat_at(parent_fd, name)
    except FileNotFoundError:
        existing = None

    if member.isdir():
        if existing is None or not stat.S_ISDIR(existing.st_mode):
            if existing is not None:
                dirfd.rmtree_at(parent_fd, name, force=True)
            os.mkdir(name, 0o777, dir_fd=parent_fd)
        with contextlib.suppress(OSError):
            os.chown(name, member.uid, member.gid, dir_fd=parent_fd, follow_symlinks=False)
        dirfd.chmod_at(parent_fd, name, stat.S_IMODE(member.mode) | stat.S_IRWXU, only_dir=True)
        deferred_dirs[dest] = (member.mtime, member.offset)
        return

    deferred_dirs.pop(dest, None)
    if existing is not None and stat.S_ISDIR(existing.st_mode):
        dirfd.rmtree_at(parent_fd, name, force=True)
        removed_dirs[dest] = member.offset
    if link_parts:
        deferred_links[dest] = _Hardlink(link_parts, member.uid, member.gid, member.offset)
    elif member.issym():
        _write_symlink(parent_fd, name, member)
    else:
        _write_regular(parent_fd, name, member, tf)


def _is_whiteout(name: str) -> bool:
    """True when *name* is an OCI whiteout marker rather than an entry."""
    return name == ".wh..wh..opq" or name.startswith(".wh.")


def _apply_whiteout(parent_fd: int, basename: str) -> None:
    """Apply the OCI whiteout *basename* inside the directory parent_fd.

    Every removal is named as (dir_fd, entry) off the descriptor the resolved
    parent was walked to, so a whiteout cannot be aimed at anything the walk
    did not open itself.
    """
    if basename == ".wh..wh..opq":
        for entry in dirfd.listdir_at(parent_fd):
            dirfd.rmtree_at(parent_fd, entry, force=True)
        return
    if basename.startswith(".wh."):
        # What the whiteout deletes is the part after the prefix, and it has
        # to name a sibling: `.wh...` slices to '..', which for a whiteout at
        # the top of a layer is the extraction root's own parent, and `.wh.`
        # and `.wh..` slice to '' and '.', which name the parent itself. None
        # of the three names a sibling, so there is nothing to delete; the
        # member is still consumed, since `.wh.*` is not an entry to write
        # into the rootfs either.
        target = basename[4:]
        if target not in ("", os.curdir, os.pardir):
            dirfd.rmtree_at(parent_fd, target, force=True)


def _write_symlink(parent_fd, name, member) -> None:
    """Write one symlink member as (parent_fd, name).

    Whatever holds the name first goes through rmtree_at, which unlinks a
    symlink rather than traversing it and empties a directory an earlier layer
    wrote however deep and however sealed the image made it. symlink(2) has no
    O_TRUNC and would only report EEXIST.
    """
    if dirfd.exists_at(parent_fd, name):
        dirfd.rmtree_at(parent_fd, name, force=True)
    try:
        os.symlink(member.linkname, name, dir_fd=parent_fd)
    except OSError:
        return
    with contextlib.suppress(OSError):
        os.chown(name, member.uid, member.gid, dir_fd=parent_fd, follow_symlinks=False)
    with contextlib.suppress(OSError):
        os.utime(name, (member.mtime, member.mtime), dir_fd=parent_fd, follow_symlinks=False)


def _safe_resolve(root: str, parts: list[str]) -> str | None:
    """Resolve *parts* beneath *root*, clamping every hop inside it.

    Returns an absolute path guaranteed to live within *root*, or None
    if a symlink loop / excessive chain is hit (caller skips the entry).
    See safe_resolve_parts, which does the work.
    """
    resolved = safe_resolve_parts(root, parts)
    if resolved is None:
        return None
    return os.path.join(root, *resolved)


def safe_resolve_parts_at(
    root_fd: int, parts: Sequence[str], *, replaced_dirs: set[_Parts] | None = None
) -> list[str] | None:
    """safe_resolve_parts() against a root the caller has pinned.

    The same walk, with every lstat and readlink taken relative to *root_fd*
    instead of composed onto a root path, so the answer describes the tree
    below the descriptor the caller validated rather than below a name it would
    have to trust a second time. What comes back is still only where the entry
    *belongs*: the components have to be re-walked with dirfd.descend_at()
    before anything is written through them.
    """
    return safe_resolve_parts(None, parts, root_fd=root_fd, replaced_dirs=replaced_dirs)


def safe_resolve_parts(
    root: str | None,
    parts: Sequence[str],
    *,
    root_fd: int | None = None,
    replaced_dirs: set[_Parts] | None = None,
) -> list[str] | None:
    """The components *parts* resolves to beneath *root*, or None.

    Walks *parts* component by component starting at *root*. Existing
    symlink components are followed, but their targets are interpreted
    relative to *root*: an absolute target re-roots at *root* and ".."
    can never ascend above it. This both blocks symlink-traversal
    escapes and matches the guest's own runtime view, where '/' is the
    rootfs, so legitimate absolute symlinks resolve to the right
    in-rootfs location. Components that don't exist yet are taken
    verbatim (a not-yet-written subtree can't be a symlink).
    A whiteout has no lower target through a symlink marked in replaced_dirs.

    Pass parent components only when the final element must not be
    followed (file/dir/symlink writes); pass the full path to resolve a
    hardlink's source file.

    With *root_fd* the walk names each level relative to that descriptor and
    *root* is unused. safe_resolve_parts_at() is the spelling for that, and it
    is what a caller holding a pinned root wants. Without it the levels are
    composed onto *root*, which is right for a tree this process made itself.

    The components come back rather than a joined path for a caller that
    means to descend them with openat(2): the walk says where the entry
    belongs, but it resolves each level by name, so a component
    re-pointed afterwards would still be followed by whatever acts on
    the result. Only re-walking the answer off a descriptor closes that.
    """
    resolved: list[str] = []
    pending = list(parts)
    link_budget = 40
    while pending:
        comp = pending.pop(0)
        if comp in ("", "."):
            continue
        if comp == "..":
            if resolved:
                resolved.pop()
            continue
        rel = os.path.join(*resolved, comp) if resolved else comp
        try:
            if root_fd is not None:
                st = os.lstat(rel, dir_fd=root_fd)
            else:
                st = os.lstat(os.path.join(typing.cast(str, root), rel))
        except OSError:
            # Doesn't exist yet (or unreadable), so it is safe as-is.
            resolved.append(comp)
            continue
        if stat.S_ISLNK(st.st_mode):
            if replaced_dirs is not None and (*resolved, comp) in replaced_dirs:
                return None
            link_budget -= 1
            if link_budget < 0:
                return None
            try:
                if root_fd is not None:
                    target = os.readlink(rel, dir_fd=root_fd)
                else:
                    target = os.readlink(os.path.join(typing.cast(str, root), rel))
            except OSError:
                return None
            tparts = target.split("/")
            if target.startswith("/"):
                resolved = []  # absolute target: re-root at *root*
            pending[:0] = tparts
        else:
            resolved.append(comp)
    return resolved


def _write_regular(parent_fd, name, member, tf) -> None:
    """Write one regular-file member as (parent_fd, name).

    open_new_at() creates a fresh inode with O_EXCL, unlinking whatever name
    was there first. That is what keeps the content inside the directory the
    walk opened even when the entry standing there is a *hardlink* to a file
    elsewhere: O_NOFOLLOW cannot tell one from an ordinary file, and an
    O_TRUNC write through it would land on the other inode.
    """
    fobj = tf.extractfile(member)
    if fobj is None:
        return
    try:
        fd, _st = dirfd.open_new_at(parent_fd, name, stat.S_IMODE(member.mode))
        try:
            with open(fd, "wb", closefd=False) as out:
                shutil.copyfileobj(fobj, out, 1 << 17)  # 128 KiB chunks
            # Ownership through the descriptor, before the mode: chown(2) drops
            # setuid and setgid whenever the caller lacks CAP_FSETID, and the
            # mode open() created with is umask-masked anyway.
            with contextlib.suppress(OSError):
                os.fchown(fd, member.uid, member.gid)
            with contextlib.suppress(OSError):
                os.fchmod(fd, stat.S_IMODE(member.mode))
        finally:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.utime(name, (member.mtime, member.mtime), dir_fd=parent_fd, follow_symlinks=False)
    finally:
        fobj.close()
