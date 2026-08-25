# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Extract a tar stream into a rootfs, member by member, safely.

One streaming extractor serves both Docker layer application and plain rootfs
tarball installs; they differ only in `strip` (leading components to drop from
each member name, >0 only for a tarball whose entries sit under a wrapper
directory) and `handle_whiteouts` (when True, OCI whiteouts, `.wh.<name>` and
opaque `.wh..wh..opq`, consume sibling entries instead of being written as
ordinary members).

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

The order of the writes carries invariants of its own. Hard links are deferred
until every regular file has been written, then both endpoints are re-resolved, so
a symlink planted by a *later* member cannot redirect either end, and the link
source exists by then. Directories get at least S_IRWXU whatever mode the archive
recorded, so later members can be written into them, and their mtimes are stamped
last, since writing into a directory bumps it. Parent descriptors are cached one
deep (`_Parents`): a tar lists its members in tree order, so consecutive entries
almost always share a parent and the descent costs about one openat per member.
Progress counts compressed bytes consumed (`ByteCounter`), so the denominator is
`os.path.getsize()` and no upfront scan is needed.

The descriptor discipline is ported from proot-distro
(https://github.com/termux/proot-distro), created by Sylirre
<sylirre@termux.dev> for the Termux project and licensed GPL-3.0, then adapted to
this project's extractor, which also carries each member's ownership.
"""

import contextlib
import os
import shutil
import stat
import sys
import typing
from collections.abc import Sequence

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.progress import ByteCounter, clear_bar, draw_bytes_bar


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
    deferred_links: list = []  # (dest parts, src parts, uid, gid)
    deferred_dirs: list = []  # (parts, mtime), stamped after all writes
    parents = _Parents(rootfs_fd)

    try:
        with open(archive_path, "rb") as raw_fh:
            counter = ByteCounter(raw_fh)
            with tarfile.open(fileobj=typing.cast(typing.Any, counter), mode="r|*") as tf:
                for member in tf:
                    _process_member(
                        member,
                        tf,
                        rootfs_fd,
                        parents,
                        strip=strip,
                        handle_whiteouts=handle_whiteouts,
                        deferred_links=deferred_links,
                        deferred_dirs=deferred_dirs,
                    )
                    draw_bytes_bar(counter.count, total_size)

        # Both endpoints are re-resolved here rather than at defer time, so a
        # symlink planted by a later member cannot redirect the read source or
        # the write dest outside the rootfs, and each answer is walked off the
        # rootfs descriptor rather than opened by name.
        for dest_parts, src_parts, uid, gid in deferred_links:
            _copy_hardlink(rootfs_fd, parents, dest_parts, src_parts, uid, gid)

        # Stamp directory mtimes last (writing files into a dir bumps it).
        for parts, mtime in reversed(deferred_dirs):
            with contextlib.suppress(OSError):
                parent_fd = parents.get(parts[:-1], create=False)
                os.utime(parts[-1], (mtime, mtime), dir_fd=parent_fd, follow_symlinks=False)
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


def _copy_hardlink(rootfs_fd, parents, dest_parts, src_parts, uid, gid) -> None:
    """Materialise one deferred hard-link member as a regular file.

    A hard link is stored as a copy of the backing file's content: the two
    endpoints of an archive's link may end up on different filesystems once
    restored, and a copy is what survives that. Mode and timestamps come across
    with it, and the member's own ownership is applied in place of the source
    file's (dirfd.copy_file_at, which is shutil.copy2 expressed against
    descriptors).
    """
    src_resolved = safe_resolve_parts_at(rootfs_fd, src_parts)
    dest_resolved = safe_resolve_parts_at(rootfs_fd, dest_parts)
    if not src_resolved or not dest_resolved:
        return
    try:
        src_fd = dirfd.descend_at(rootfs_fd, src_resolved[:-1])
    except OSError:
        return
    try:
        try:
            st = dirfd.lstat_at(src_fd, src_resolved[-1])
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode):
            # The test must not follow the link: a hard-link member naming a
            # symlink has no content of its own to copy.
            return
        try:
            dst_fd = parents.get(dest_resolved[:-1])
        except OSError:
            return
        dirfd.unlink_quietly(dst_fd, dest_resolved[-1])
        with contextlib.suppress(OSError):
            dirfd.copy_file_at(src_fd, src_resolved[-1], dst_fd, dest_resolved[-1], st, owner=(uid, gid))
    finally:
        os.close(src_fd)


def _process_member(member, tf, rootfs_fd, parents, *, strip, handle_whiteouts, deferred_links, deferred_dirs):
    if member.isblk() or member.ischr() or member.isfifo():
        return

    parts = member.name.lstrip("/").rstrip("/").split("/")
    if len(parts) <= strip:
        return
    rel_parts = parts[strip:]
    if any(p in ("..", "") for p in rel_parts):
        return

    rel_path = "/".join(rel_parts)
    if not rel_path or rel_parts[-1] == os.curdir:
        # A trailing '.' names the directory the member already sits in rather
        # than an entry of its own, so writing it would act on that directory:
        # a symlink member takes its whole contents with it. Interior '.'
        # components stay allowed, since OCI layers spell their paths './foo'
        # as a matter of course and safe_resolve_parts drops them on the way
        # through.
        return

    # Resolve the destination's parent through any pre-existing symlink
    # components, clamping every hop inside the rootfs (see the module
    # comment). The final component is deliberately *not* followed so we
    # operate on the entry itself, never on whatever a same-named symlink
    # points at.
    parent_parts = safe_resolve_parts_at(rootfs_fd, rel_parts[:-1])
    if parent_parts is None:
        return
    name = rel_parts[-1]

    if handle_whiteouts and _is_whiteout(name):
        # No parent is created for a whiteout: it only ever removes, and a
        # directory that is not there has nothing in it to remove.
        try:
            parent_fd = parents.get(parent_parts, create=False)
        except OSError:
            return
        _apply_whiteout(parent_fd, name)
        return

    parent_fd = parents.get(parent_parts, create=True)

    if member.isdir():
        # A symlink already occupying this name would make the mkdir (and the
        # chmod/chown/utime below) act on its target, so drop it first:
        # overlay semantics replace a symlink with a real dir.
        try:
            st = dirfd.lstat_at(parent_fd, name)
        except OSError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            dirfd.unlink_quietly(parent_fd, name)
        try:
            os.mkdir(name, 0o777, dir_fd=parent_fd)
        except FileExistsError:
            # An existing directory is tolerated and nothing else: a plain
            # file standing here ends the extraction rather than being
            # written around.
            existing = None
            with contextlib.suppress(OSError):
                existing = dirfd.lstat_at(parent_fd, name)
            if existing is None or not stat.S_ISDIR(existing.st_mode):
                raise
        # Ownership before the mode: chown(2) drops setgid whenever the caller
        # lacks CAP_FSETID, and a shared build directory carries it.
        with contextlib.suppress(OSError):
            os.chown(name, member.uid, member.gid, dir_fd=parent_fd, follow_symlinks=False)
        dirfd.chmod_at(parent_fd, name, stat.S_IMODE(member.mode) | stat.S_IRWXU)
        deferred_dirs.append(([*parent_parts, name], member.mtime))

    elif member.issym():
        _write_symlink(parent_fd, name, member)

    elif member.islnk():
        _defer_hardlink(member, strip, rel_parts, deferred_links)

    elif member.isreg():
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
        try:
            entries = dirfd.listdir_at(parent_fd)
        except OSError:
            return
        for entry in entries:
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


def _defer_hardlink(member, strip, rel_parts, deferred_links):
    """Queue a hardlink for copy after all regular files are written.

    The linkname is filtered identically to member.name: leading slashes are
    stripped, the first *strip* components dropped, and any ".." or empty
    component drops the entry. Without this a malicious archive could point
    linkname at a host path (e.g. "../../etc/shadow") and the copy would
    resolve it through the rootfs prefix, copying host content into the
    member-defined dest inside the rootfs.

    Only the (validated) relative components of both endpoints are stored, with
    the member's ownership; both are resolved with safe_resolve_parts_at() at
    copy time so a symlink planted by a later member can't redirect the read
    source or the write dest out of the rootfs, and the answers are walked off
    the rootfs descriptor rather than opened by name.
    """
    lparts = member.linkname.lstrip("/").rstrip("/").split("/")
    if len(lparts) <= strip:
        return
    rel_lparts = lparts[strip:]
    if any(p in ("..", "") for p in rel_lparts):
        return
    deferred_links.append((rel_parts, rel_lparts, member.uid, member.gid))


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


def safe_resolve_parts_at(root_fd: int, parts: Sequence[str]) -> list[str] | None:
    """safe_resolve_parts() against a root the caller has pinned.

    The same walk, with every lstat and readlink taken relative to *root_fd*
    instead of composed onto a root path, so the answer describes the tree
    below the descriptor the caller validated rather than below a name it would
    have to trust a second time. What comes back is still only where the entry
    *belongs*: the components have to be re-walked with dirfd.descend_at()
    before anything is written through them.
    """
    return safe_resolve_parts(None, parts, root_fd=root_fd)


def safe_resolve_parts(
    root: str | None,
    parts: Sequence[str],
    *,
    root_fd: int | None = None,
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
    O_TRUNC write through it would land on the other inode. A directory in the
    way still ends the extraction, as open(dest, "wb") did on EISDIR.
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
