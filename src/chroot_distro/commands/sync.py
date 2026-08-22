"""Mirror a source path onto a destination path, optionally pruning orphans.

Change detection compares type, size and modification time, or a CRC32 digest
with `--checksum`; neither is an integrity check. Both files and directories are
accepted as the source: symlinks inside a tree are copied as-is while one named
as the source itself is followed, hardlinks become independent copies, and
special files (block, char, FIFO, socket) are skipped inside a tree with a
warning and refused as the whole source. Ownership is never changed. Modes and
timestamps are preserved for directories as well as files, and one that changed
on its own is applied without rewriting the content — unless the destination
carries a second link, the one case where that would touch an inode this command
did not create (see `_refresh_file_metadata`). A sparsely stored source is
written back sparsely. With `--delete`, destination entries the source has no
counterpart for are removed after the mirror pass; a source sitting *inside* the
destination is refused rather than pruned as one of them, and nothing is pruned
at all when the source could not be listed.

An entry that cannot be read or written is reported and stepped over, so one bad
file does not cost the rest of the tree, and the command exits non-zero when any
were — the way rsync does. That holds for every kind of entry: a directory that
cannot be created, a symlink the destination filesystem will not hold (vfat, and
so /sdcard), and an orphan `--delete` cannot remove.

Both roots are pinned by `paths.pin_path` and every level below them is reached
through `chroot_distro.dirfd`, so nothing here resolves a path a container
process could have re-pointed in the meantime. Two consequences worth
remembering when editing: a destination entry that is not a directory where the
source has one is unlinked and replaced, never descended into, because a symlink
there may lead outside the container and the whole subtree would follow it; and
the permission fix-ups go through `dirfd.make_writable`, which names a
descriptor, because chmod(2) has no symlink-relative form on Linux and naming an
entry would apply the mode to whatever a planted link points at.

The work is three passes: `_collect_rels` records the source's relative paths,
`_mirror_at` writes, and `_collect_extras_at` / `_remove_extras_at` prune. All
three carry directory fds down an explicit stack, so the number of open fds
follows the depth of the tree rather than its size.

Ported from proot-distro (https://github.com/termux/proot-distro), created by
Sylirre <sylirre@termux.dev> for the Termux project and licensed GPL-3.0, then
adapted to chroot-distro's message helpers and path resolution.
"""

import contextlib
import os
import stat
import sys
import zlib
from contextlib import ExitStack
from typing import Any

from chroot_distro import dirfd
from chroot_distro.message import crit_error, log_error, log_info, quote_path, warn
from chroot_distro.paths import (
    PinnedPath,
    container_locks_for_spec_pair,
    pin_path,
    refuse_src_dest_overlap,
    resolve_container_child,
    resolve_container_path,
)
from chroot_distro.progress import clear_bar, draw_count_bar

_TMP_SUFFIX = ".~cd_sync"

_META_OK, _META_FIXED, _META_REWRITE = range(3)


class _Ctx:
    """State threaded through the three passes.

    `src_rels` holds every relative path seen in the source. The counting pass
    fills it and the mirror pass adds to it, because the two look at the tree at
    different moments: an entry created in between is mirrored by the second, and
    `--delete` going by the first pass alone would remove the file it had just
    written.

    `skipped_rels` holds the paths the mirror pass did not write. Two things
    follow from an entry being in there: `--delete` leaves the matching
    destination alone, since it has no counterpart to compare against and
    pruning it would delete data on the strength of a transfer that never
    happened, and the command reports the transfer incomplete.

    `failures` counts entries that could not be read or written. Counted rather
    than fatal — one entry must not abandon the rest of the tree — but the
    command still exits non-zero, as rsync does for the same.

    `root_unreadable` is set when the source root itself could not be listed,
    which leaves `src_rels` empty and every destination entry looking like an
    orphan. `--delete` must not run on that.
    """

    def __init__(self, src_root: str, dest_spec: str, verbose: bool, use_checksum: bool) -> None:
        self.src_root = src_root
        self.dest_spec = dest_spec
        self.verbose = verbose
        self.use_checksum = use_checksum
        self.total = 1
        self.done = 0
        self.src_rels: set[str] = set()
        self.skipped_rels: set[str] = set()
        self.failures = 0
        self.root_unreadable = False

    def saw(self, rel: str) -> None:
        """Record a source entry, keeping the progress total in step.

        The total is recomputed rather than incremented because the passes
        overlap: pass 1 fills src_rels and pass 2 adds whatever appeared since, so
        a count that only ever grew would run past its own total.
        """
        self.src_rels.add(rel)
        self.total = max(len(self.src_rels), 1)

    def note_failure(self, rel: str) -> None:
        """Record an entry that was skipped, and why it matters later.

        Idempotent: both passes touch the same tree, so a persistently unreadable
        entry is met twice and counting it twice would report one bad file as two.
        """
        if rel not in self.skipped_rels:
            self.skipped_rels.add(rel)
            self.failures += 1

    def shown(self, rel: str) -> str:
        """The destination path as the user typed it, for messages."""
        return quote_path(os.path.join(self.dest_spec, rel) if rel else self.dest_spec)

    def src_shown(self, rel: str) -> str:
        """The source path, for messages about the reading side."""
        return quote_path(os.path.join(self.src_root, rel) if rel else self.src_root)

    def progress(self) -> None:
        """Draw the count bar, unless per-entry lines are already being logged."""
        if not self.verbose:
            draw_count_bar(self.done, self.total, unit="files")


def _rel(rel: str, name: str) -> str:
    """Join a relative directory path and an entry name."""
    return f"{rel}/{name}" if rel else name


def _is_special(mode: int) -> bool:
    """True for a block or character device, a FIFO or a socket."""
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _checksum_at(dir_fd: int, name: str) -> int:
    """CRC32 of the regular file *name* under dir_fd."""
    fd, _ = dirfd.open_regular_at(dir_fd, name, os.O_RDONLY)
    try:
        crc = 0
        with open(fd, "rb", closefd=False) as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                crc = zlib.crc32(chunk, crc)
        return crc
    finally:
        os.close(fd)


def _needs_update(
    src_fd: int,
    src_name: str,
    src_st: os.stat_result,
    dst_fd: int,
    dst_name: str,
    use_checksum: bool,
) -> bool:
    """True when the destination must be rewritten from the source.

    A type or size mismatch always updates. With `--checksum` the CRC32 digests
    are compared, otherwise the whole-second modification times, which is the
    granularity a destination filesystem storing less precision than the source
    can be held to.
    """
    try:
        dst_st = dirfd.lstat_at(dst_fd, dst_name)
    except OSError:
        return True
    if stat.S_IFMT(src_st.st_mode) != stat.S_IFMT(dst_st.st_mode):
        return True
    if src_st.st_size != dst_st.st_size:
        return True
    if use_checksum:
        try:
            return _checksum_at(src_fd, src_name) != _checksum_at(dst_fd, dst_name)
        except OSError:
            return True
    return int(src_st.st_mtime) != int(dst_st.st_mtime)


def _unlink_robust(dst_fd: int, name: str, is_dir: bool = False) -> None:
    """Remove *name* under dst_fd, retrying with a chmod on EPERM.

    Raises OSError when the entry survives, which every caller turns into a
    per-entry failure: ending the process on the spot is the one thing a transfer
    must not do for a single entry.
    """
    try:
        if is_dir:
            dirfd.rmtree_at(dst_fd, name)
        else:
            os.unlink(name, dir_fd=dst_fd)
        return
    except PermissionError:
        pass
    dirfd.make_writable(dst_fd)
    if is_dir:
        dirfd.rmtree_at(dst_fd, name, force=True)
    else:
        os.unlink(name, dir_fd=dst_fd)


def _sync_dir(dst_fd: int, name: str) -> bool:
    """Ensure *name* exists under dst_fd as a directory.

    Returns True when the directory was newly created; raises OSError when it
    could not be, which the caller reports and steps over.

    Anything else standing at the name is replaced rather than descended into,
    which is what rsync does and what safety requires: inside a container rootfs
    a symlink there may point at the host filesystem, and every file of the
    subtree would then be written outside the container.

    The directory is created writable and given the source's metadata by
    `_mirror_at` once its contents are in. mkdir's mode is umask-masked and so
    cannot preserve the source mode anyway.
    """
    try:
        dst_st: os.stat_result | None = dirfd.lstat_at(dst_fd, name)
    except OSError:
        dst_st = None

    if dst_st is not None and not stat.S_ISDIR(dst_st.st_mode):
        _unlink_robust(dst_fd, name)
        dst_st = None

    if dst_st is not None:
        return False

    try:
        os.mkdir(name, 0o700, dir_fd=dst_fd)
    except PermissionError:
        dirfd.make_writable(dst_fd)
        os.mkdir(name, 0o700, dir_fd=dst_fd)
    return True


def _sync_symlink(
    src_fd: int,
    src_name: str,
    dst_fd: int,
    dst_name: str,
    src_st: os.stat_result | None = None,
) -> bool:
    """Copy a symlink as-is. Returns True when the destination changed.

    Raises OSError when the link could not be read or written, which the caller
    reports and steps over: a destination filesystem with no symlinks at all
    (vfat, and so /sdcard) would otherwise fail on the first one and leave
    everything after it untransferred.
    """
    target = os.readlink(src_name, dir_fd=src_fd)

    try:
        dst_st: os.stat_result | None = dirfd.lstat_at(dst_fd, dst_name)
    except OSError:
        dst_st = None

    if dst_st is not None:
        if stat.S_ISLNK(dst_st.st_mode) and os.readlink(dst_name, dir_fd=dst_fd) == target:
            return False
        _unlink_robust(dst_fd, dst_name, stat.S_ISDIR(dst_st.st_mode))

    try:
        os.symlink(target, dst_name, dir_fd=dst_fd)
    except PermissionError:
        dirfd.make_writable(dst_fd)
        os.symlink(target, dst_name, dir_fd=dst_fd)

    if src_st is not None:
        dirfd.set_times_at(dst_fd, dst_name, src_st)
    return True


def _refresh_file_metadata(src_st: os.stat_result, dst_fd: int, dst_name: str) -> int:
    """Bring an up-to-date file's mode and times into line with the source's.

    Returns _META_OK when there was nothing to do, _META_FIXED when the entry was
    corrected in place, or _META_REWRITE to ask the caller for a full rewrite.

    _needs_update compares type, size and mtime — never permissions — so a
    `chmod +x` with no other change would leave the destination on the old mode
    for good, and `--checksum` would leave the times behind in the same way.

    Mode and times are applied to a descriptor, so the entry cannot be swapped
    between the test and the change, and open_regular_at refuses anything but a
    regular file.

    A destination carrying more than one link is not touched at all. This is the
    one place a transfer would otherwise write to an inode it did not create, and
    a hardlink is precisely what that rule exists for: nothing distinguishes one
    a guest made to a *host* file from an ordinary rootfs entry, so an fchmod here
    would hand a container the mode of any file the host had put within its reach.
    The rewrite goes through _sync_file, whose temp-and-rename leaves the other
    name pointing at the old inode.
    """
    try:
        fd, dst_st = dirfd.open_regular_at(dst_fd, dst_name, os.O_RDONLY)
    except OSError:
        return _META_OK
    try:
        want = stat.S_IMODE(src_st.st_mode)
        stale = int(dst_st.st_mtime) != int(src_st.st_mtime)
        if stat.S_IMODE(dst_st.st_mode) == want and not stale:
            return _META_OK
        if dst_st.st_nlink != 1:
            return _META_REWRITE
        if stat.S_IMODE(dst_st.st_mode) != want:
            os.fchmod(fd, want)
        if stale:
            os.utime(fd, ns=(src_st.st_atime_ns, src_st.st_mtime_ns))
        return _META_FIXED
    except OSError:
        return _META_OK
    finally:
        os.close(fd)


def _sync_file(
    src_fd: int,
    src_name: str,
    src_st: os.stat_result,
    dst_fd: int,
    dst_name: str,
    ctx: _Ctx,
    rel: str,
) -> bool:
    """Copy a regular file, preserving mode and mtime.

    Returns True when the destination now matches the source, False when the entry
    was left as it was — which is what tells `--delete` to keep its hands off the
    destination.

    Writes a sibling temp file and renames it into place, so a partial write never
    leaves the destination corrupt and an existing symlink at the destination name
    is replaced rather than written through. The temp file is created O_EXCL
    (dirfd.open_new_at), so a name already standing there is removed rather than
    written into — it may be a hardlink to a file outside the container, which
    nothing about the entry would show.

    A directory standing where the source has a regular file is refused, as rsync
    refuses it, and named for what it is rather than surfacing as EISDIR on a temp
    file the user never asked about. `_sync_dir` does clear a *non*-directory in
    the other direction, because a symlink there can lead out of the container and
    a directory cannot.

    Every failure here is per-entry: reported, counted, and stepped over. The temp
    file is removed on any exception, Ctrl-C included, or an interrupted sync would
    leave a half-copy sitting next to the real one.
    """
    where = ctx.shown(rel)
    tmp = dirfd.temp_name(dst_name, _TMP_SUFFIX)
    mode = stat.S_IMODE(src_st.st_mode)

    try:
        dst_st: os.stat_result | None = dirfd.lstat_at(dst_fd, dst_name)
    except OSError:
        dst_st = None
    if dst_st is not None and stat.S_ISDIR(dst_st.st_mode):
        warn(f"cannot replace directory '{where}' with a file, skipping.")
        ctx.note_failure(rel)
        return False

    try:
        sfd, sfd_st = dirfd.open_regular_at(src_fd, src_name, os.O_RDONLY)
    except OSError as exc:
        warn(f"cannot read '{ctx.src_shown(rel)}': {quote_path(str(exc))}")
        ctx.note_failure(rel)
        return False

    try:
        try:
            try:
                tfd, _ = dirfd.open_new_at(dst_fd, tmp, mode)
            except PermissionError:
                dirfd.make_writable(dst_fd)
                tfd, _ = dirfd.open_new_at(dst_fd, tmp, mode)
            try:
                dirfd.copy_data(sfd, tfd, sfd_st)
                dirfd.copy_metadata(sfd, tfd, src_st)
            finally:
                os.close(tfd)
            os.replace(tmp, dst_name, src_dir_fd=dst_fd, dst_dir_fd=dst_fd)
        except OSError as exc:
            dirfd.unlink_quietly(dst_fd, tmp)
            warn(f"cannot write to '{where}': {quote_path(str(exc))}")
            ctx.note_failure(rel)
            return False
        except BaseException:
            dirfd.unlink_quietly(dst_fd, tmp)
            raise
    finally:
        os.close(sfd)
    return True


def _record_level(src_fd: int, rel: str, ctx: _Ctx) -> list[str]:
    """Add one level's entries to ctx.src_rels; return its subdirectory names.

    A root that cannot be listed sets ctx.root_unreadable rather than joining
    skipped_rels, which cannot express "all of it": every relative path is below
    the root, and src_rels stays empty, which makes every destination entry look
    like an orphan. `_prune` declines to run on that.
    """
    try:
        names = dirfd.listdir_at(src_fd)
    except OSError:
        if rel:
            ctx.note_failure(rel)
        else:
            ctx.root_unreadable = True
            ctx.failures += 1
        warn(f"directory '{ctx.src_shown(rel)}' is not readable, skipping.")
        return []

    subdirs = []
    for name in names:
        child = _rel(rel, name)
        ctx.saw(child)
        try:
            st = dirfd.lstat_at(src_fd, name)
        except OSError as exc:
            warn(f"cannot stat '{ctx.src_shown(child)}': {quote_path(str(exc))}")
            ctx.note_failure(child)
            continue
        if stat.S_ISDIR(st.st_mode):
            subdirs.append(name)
    return subdirs


def _collect_rels(src_fd: int, rel: str, ctx: _Ctx) -> None:
    """Record every entry under src_fd into ctx.src_rels.

    Directories that cannot be opened are warned about once, here, and added to
    ctx.skipped_rels so that neither the mirror nor `--delete` touches the
    matching destination subtree.

    Walked with an explicit stack, as all three passes are: how deep the tree goes
    is not this command's decision, and recursing would turn one deeper than the
    interpreter's limit into a traceback (see dirfd.copy_tree_at).

    Frame layout: [fd, None, rel, pending subdirectory names, owned] — the shape
    dirfd.close_frames expects.
    """
    stack: list[list[Any]] = [[src_fd, None, rel, None, False]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, cur, pending, owned = frame
            if pending is None:
                pending = frame[3] = _record_level(fd, cur, ctx)
                pending.reverse()
            if not pending:
                levels.pop()
                if owned:
                    os.close(fd)
                continue

            name = pending.pop()
            child = _rel(cur, name)
            try:
                sub = dirfd.opendir_at(fd, name)
            except OSError:
                ctx.note_failure(child)
                warn(f"directory '{ctx.src_shown(child)}' is not readable, skipping.")
                continue
            levels.push([sub, None, child, None, True])
    except BaseException:
        dirfd.close_frames(stack)
        raise


def _mirror_entries(src_fd: int, dst_fd: int, rel: str, ctx: _Ctx) -> list[str]:
    """Write one level's non-directory entries; return its subdirectory names.

    An entry this cannot write joins ctx.skipped_rels, which keeps `--delete` off
    the destination that stands in its place: without it a source entry the mirror
    stepped over still counted as present in the source, so the prune pass walked
    into whatever the destination held under that name and emptied it.

    Every name seen here also joins ctx.src_rels, because the counting pass ran
    earlier and the source may have moved on since.

    A special file is never mirrored, so the destination under that name is not
    this transfer's to judge, and it is said out loud: one that quietly failed to
    arrive is not something a user should have to diff a tree to discover.
    """
    try:
        names = dirfd.listdir_at(src_fd)
    except OSError as exc:
        if rel not in ctx.skipped_rels:
            warn(f"cannot read directory '{ctx.src_shown(rel)}': {quote_path(str(exc))}")
        ctx.note_failure(rel)
        return []

    subdirs = []
    for name in names:
        child = _rel(rel, name)
        ctx.saw(child)
        try:
            src_st = dirfd.lstat_at(src_fd, name)
        except OSError as exc:
            warn(f"cannot stat '{ctx.src_shown(child)}': {quote_path(str(exc))}")
            ctx.note_failure(child)
            ctx.done += 1
            ctx.progress()
            continue

        mode = src_st.st_mode

        if _is_special(mode):
            warn(f"skipping special file '{ctx.src_shown(child)}'.")
            ctx.skipped_rels.add(child)
        elif stat.S_ISDIR(mode):
            try:
                created = _sync_dir(dst_fd, name)
            except OSError as exc:
                warn(f"cannot create directory '{ctx.shown(child)}': {quote_path(str(exc))}")
                ctx.note_failure(child)
            else:
                subdirs.append(name)
                if ctx.verbose and created:
                    log_info(f"({ctx.done + 1}/{ctx.total}) New directory: {ctx.shown(child)}")
        elif stat.S_ISLNK(mode):
            op = "Modified" if dirfd.exists_at(dst_fd, name) else "New"
            try:
                changed = _sync_symlink(src_fd, name, dst_fd, name, src_st)
            except OSError as exc:
                warn(f"cannot copy symlink '{ctx.src_shown(child)}': {quote_path(str(exc))}")
                ctx.note_failure(child)
            else:
                if changed and ctx.verbose:
                    log_info(f"({ctx.done + 1}/{ctx.total}) {op} symlink: {ctx.shown(child)}")
        elif stat.S_ISREG(mode):
            outcome = (
                _META_REWRITE
                if _needs_update(src_fd, name, src_st, dst_fd, name, ctx.use_checksum)
                else _refresh_file_metadata(src_st, dst_fd, name)
            )
            if outcome == _META_REWRITE:
                op = "Modified" if dirfd.exists_at(dst_fd, name) else "New"
                if _sync_file(src_fd, name, src_st, dst_fd, name, ctx, child) and ctx.verbose:
                    log_info(f"({ctx.done + 1}/{ctx.total}) {op} file: {ctx.shown(child)}")
            elif outcome == _META_FIXED and ctx.verbose:
                log_info(f"({ctx.done + 1}/{ctx.total}) Metadata: {ctx.shown(child)}")

        ctx.done += 1
        ctx.progress()

    return subdirs


def _mirror_at(src_fd: int, dst_fd: int, rel: str, ctx: _Ctx) -> None:
    """Mirror the directory open at src_fd into the one at dst_fd.

    A level's metadata is applied on the way back up, against the descended fds
    rather than the names: chmod(2) has no symlink-relative form on Linux, so
    naming the entry would hand a swapped-in link's target the mode change.
    Applying it last also keeps a read-only source directory (0555 and friends)
    writable while its own contents are still being written, and is the only
    moment its mtime can be set, since writing the contents bumps it.

    The source fd is pushed before the destination is opened, so a failure there
    leaves it on the stack for dirfd.close_frames. A refusal on either side means
    the entry turned into a symlink since it was listed; anything else on the
    source side was already reported by `_collect_rels`.

    Frame layout: [src_fd, dst_fd, rel, pending subdirectories, owned].
    """
    stack: list[list[Any]] = [[src_fd, dst_fd, rel, None, False]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            sfd, dfd, cur, pending, owned = frame
            if pending is None:
                pending = frame[3] = _mirror_entries(sfd, dfd, cur, ctx)
                pending.reverse()
            if not pending:
                levels.pop()
                if owned:
                    try:
                        dirfd.copy_metadata(sfd, dfd)
                    finally:
                        os.close(dfd)
                        os.close(sfd)
                continue

            name = pending.pop()
            child = _rel(cur, name)
            try:
                sub_src = dirfd.opendir_at(sfd, name)
            except OSError as exc:
                if dirfd.is_refusal(exc):
                    warn(
                        f"source '{ctx.src_shown(child)}' changed to a symlink "
                        f"during the transfer, skipping."
                    )
                ctx.note_failure(child)
                continue
            levels.push([sub_src, None, child, None, True])
            try:
                stack[-1][1] = dirfd.opendir_at(dfd, name)
            except OSError as exc:
                levels.pop()
                os.close(sub_src)
                if dirfd.is_refusal(exc):
                    warn(f"'{ctx.shown(child)}' changed to a symlink during the transfer, skipping.")
                else:
                    warn(f"cannot descend into '{ctx.shown(child)}': {quote_path(str(exc))}")
                ctx.note_failure(child)
    except BaseException:
        dirfd.close_frames(stack)
        raise


def _listing_at(dst_fd: int) -> list[str]:
    """One level's entry names, reversed so pop() takes them in order.

    A level that cannot be read yields nothing: both prune passes step over what
    they cannot see rather than guessing at it.
    """
    try:
        names = dirfd.listdir_at(dst_fd)
    except OSError:
        return []
    names.reverse()
    return names


def _collect_extras_at(dst_fd: int, rel: str, ctx: _Ctx, extras: list[tuple[str, bool]]) -> None:
    """Collect destination entries that have no counterpart in the source.

    An extra directory is captured whole and not descended into; a symlink is
    captured as a plain entry so it is unlinked rather than walked, which the
    lstat guarantees — S_ISDIR is already false for one. Subtrees the mirror pass
    could not write are left alone (ctx.skipped_rels).

    Frame layout: [fd, None, rel, pending names, owned].
    """
    stack: list[list[Any]] = [[dst_fd, None, rel, None, False]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, cur, pending, owned = frame
            if pending is None:
                pending = frame[3] = _listing_at(fd)
            if not pending:
                levels.pop()
                if owned:
                    os.close(fd)
                continue

            name = pending.pop()
            child = _rel(cur, name)
            if child in ctx.skipped_rels:
                continue
            try:
                st = dirfd.lstat_at(fd, name)
            except OSError:
                continue
            is_dir = stat.S_ISDIR(st.st_mode)

            if child not in ctx.src_rels:
                extras.append((child, is_dir))
            elif is_dir:
                try:
                    sub = dirfd.opendir_at(fd, name)
                except OSError:
                    continue
                levels.push([sub, None, child, None, True])
    except BaseException:
        dirfd.close_frames(stack)
        raise


def _restore_dir_metadata(fd: int, saved_st: os.stat_result | None) -> None:
    """Put back the mode and times the prune pass disturbed.

    Removing an entry bumps its directory's mtime, and clearing a write-protected
    one goes through dirfd.make_writable first, which leaves u+rwx behind. Both
    undo what the mirror settled, and the prune runs after it, so a directory that
    happened to contain an orphan would come out of `--delete` stamped with the
    moment of the sync and, if it was read-only, 0755 instead of its own mode.
    """
    if saved_st is None:
        return
    with contextlib.suppress(OSError):
        os.fchmod(fd, stat.S_IMODE(saved_st.st_mode))
    with contextlib.suppress(OSError):
        os.utime(fd, ns=(saved_st.st_atime_ns, saved_st.st_mtime_ns))


def _remove_extras_at(
    dst_fd: int,
    rel: str,
    targets: dict[str, bool],
    ctx: _Ctx,
    counter: list[int],
) -> None:
    """Delete the entries named in *targets*, walking by fd.

    Each level's metadata is stat'ed before anything in it goes and restored once
    the level and everything below it are done, since removing a descendant bumps
    this level's mtime just as removing an entry does.

    Frame layout: [fd, None, rel, pending names, pre-delete stat, owned].
    """
    stack: list[list[Any]] = [[dst_fd, None, rel, None, None, False]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, cur, pending, saved_st, owned = frame
            if pending is None:
                pending = frame[3] = _listing_at(fd)
                try:
                    saved_st = frame[4] = os.fstat(fd)
                except OSError:
                    saved_st = frame[4] = None
            if not pending:
                levels.pop()
                _restore_dir_metadata(fd, saved_st)
                if owned:
                    os.close(fd)
                continue

            name = pending.pop()
            child = _rel(cur, name)
            if child in targets:
                counter[0] += 1
                if ctx.verbose:
                    log_info(f"({counter[0]}/{counter[1]}) Delete: {ctx.shown(child)}")
                try:
                    _unlink_robust(fd, name, targets[child])
                except OSError as exc:
                    warn(f"cannot delete '{ctx.shown(child)}': {quote_path(str(exc))}")
                    ctx.note_failure(child)
                continue
            if child in ctx.skipped_rels:
                continue
            try:
                st = dirfd.lstat_at(fd, name)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    sub = dirfd.opendir_at(fd, name)
                except OSError:
                    continue
                levels.push([sub, None, child, None, None, True])
    except BaseException:
        dirfd.close_frames(stack)
        raise


def command_sync(args) -> None:
    """Mirror *src* to *dest*, optionally deleting orphaned entries."""
    src = args.source
    dest = args.destination
    verbose = getattr(args, "verbose", False)
    use_checksum = getattr(args, "checksum", False)
    delete = getattr(args, "delete", False)

    with ExitStack() as stack:
        for lock in container_locks_for_spec_pair(src, dest, command="sync"):
            stack.enter_context(lock)
        _do_sync(src, dest, verbose, use_checksum, delete)


def _do_sync(src: str, dest: str, verbose: bool, use_checksum: bool, delete: bool) -> None:
    """Resolve and pin both roots, then mirror the source onto the destination.

    Both endpoints come back with their own final component resolved — the
    container side by the chroot walk, the host side by realpath — so
    `sync /sdcard box:/x` transfers the directory `/sdcard` points at and a
    destination link is written where it leads, as rsync and cp both do. Links
    *within* the tree are preserved either way; only the endpoints are followed.
    Resolving the destination here rather than leaving it to pin_path is what the
    overlap check depends on: a host path is not walked component by component, so
    pin_path would follow an endpoint link without ever being able to refuse one
    leading back into the source.

    A device, FIFO or socket named as the whole source is refused for the message,
    and `--delete` is refused without a directory source: pruning is defined
    against the contents of one, and with a single file there is nothing to
    enumerate, so accepting the flag would quietly ignore it.

    inside=True on both pins for a directory sync, because everything is written
    *underneath* the roots and a root that became a symlink must be refused rather
    than followed. create=True makes the destination root along that same walk;
    os.makedirs() on the path would follow a symlink planted after the resolve and
    build the tree outside the container before the pin could refuse. Both are tied
    to src_is_dir deliberately: rsync creates the destination directory of a
    directory transfer but will not invent the parents a single file is addressed
    through, which is why `copy` and `sync` differ here.
    """
    src_path = resolve_container_path(src)
    dest_path = resolve_container_path(dest)

    try:
        src_st = os.lstat(src_path)
    except OSError:
        crit_error(f"source path '{src}' does not exist.")
        sys.exit(1)

    src_is_dir = stat.S_ISDIR(src_st.st_mode)

    if not (src_is_dir or stat.S_ISREG(src_st.st_mode) or stat.S_ISLNK(src_st.st_mode)):
        crit_error(f"cannot sync '{src}': not a regular file or directory.")
        sys.exit(1)

    if src_is_dir and not os.access(src_path, os.R_OK | os.X_OK):
        crit_error(f"source directory '{src}' is not readable.")
        sys.exit(1)

    if delete and not src_is_dir:
        crit_error("option '--delete' needs a directory as the source.")
        sys.exit(1)

    if not src_is_dir and os.path.isdir(dest_path):
        dest_path = resolve_container_child(dest, dest_path, os.path.basename(src_path))

    refuse_src_dest_overlap(src, src_path, dest, dest_path, pruning=delete)

    log_info("Synchronizing files...")
    log_info(f"Source: '{quote_path(src_path)}'")
    log_info(f"Destination: '{quote_path(dest_path)}'")

    ctx = _Ctx(src_path, dest, verbose, use_checksum)

    with ExitStack() as pins:
        src_pin = pins.enter_context(pin_path(src, src_path, inside=src_is_dir))
        dest_pin = pins.enter_context(pin_path(dest, dest_path, inside=src_is_dir, create=src_is_dir))
        try:
            if src_is_dir:
                _sync_directory(src_pin, dest_pin, ctx, delete)
            else:
                _sync_single(src_pin, dest_pin, src_st, ctx)
        except KeyboardInterrupt:
            clear_bar()
            log_error("Aborted by user.")
            sys.exit(1)
        except OSError as exc:
            clear_bar()
            crit_error(quote_path(str(exc)))
            sys.exit(1)

    clear_bar()
    if ctx.failures:
        plural = "entry" if ctx.failures == 1 else "entries"
        crit_error(f"{ctx.failures} {plural} could not be transferred.")
        sys.exit(1)
    log_info("Finished synchronizing.")


def _sync_single(src_pin: PinnedPath, dest_pin: PinnedPath, src_st: os.stat_result, ctx: _Ctx) -> None:
    """Sync a source that is a single file or symlink.

    The type was settled in _do_sync; the tests below are what is left if it
    changed since, in which case there is nothing to transfer. Failures are
    reported per-entry even though the entry is the whole transfer, so the message
    and the exit status keep the shape they have for a tree.
    """
    mode = src_st.st_mode
    if _is_special(mode) or not (stat.S_ISLNK(mode) or stat.S_ISREG(mode)):
        warn(f"source '{ctx.src_shown('')}' is no longer a regular file or directory, skipping.")
        ctx.note_failure("")
        return
    if stat.S_ISLNK(mode):
        try:
            _sync_symlink(src_pin.dir_fd, src_pin.leaf, dest_pin.dir_fd, dest_pin.leaf, src_st)
        except OSError as exc:
            warn(f"cannot copy symlink '{ctx.shown('')}': {quote_path(str(exc))}")
            ctx.note_failure("")
        return
    outcome = (
        _META_REWRITE
        if _needs_update(src_pin.dir_fd, src_pin.leaf, src_st, dest_pin.dir_fd, dest_pin.leaf, ctx.use_checksum)
        else _refresh_file_metadata(src_st, dest_pin.dir_fd, dest_pin.leaf)
    )
    if outcome == _META_REWRITE:
        _sync_file(src_pin.dir_fd, src_pin.leaf, src_st, dest_pin.dir_fd, dest_pin.leaf, ctx, "")


def _sync_directory(src_pin: PinnedPath, dest_pin: PinnedPath, ctx: _Ctx, delete: bool) -> None:
    """Sync a directory source: count, mirror, then optionally prune.

    The root's own metadata is applied last of all: the source mode may take the
    write bit off the directory everything above still had to write into, and both
    the mirror and the prune bump its mtime.
    """
    src_fd = dirfd.reopen(src_pin.dir_fd, src_pin.leaf)
    try:
        dst_fd = dirfd.reopen(dest_pin.dir_fd, dest_pin.leaf)
        try:
            _collect_rels(src_fd, "", ctx)
            _mirror_at(src_fd, dst_fd, "", ctx)
            clear_bar()

            if delete:
                _prune(dst_fd, ctx)
            dirfd.copy_metadata(src_fd, dst_fd)
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


def _prune(dst_fd: int, ctx: _Ctx) -> None:
    """Remove destination entries the source has no counterpart for.

    Declined outright when the source root could not be listed: ctx.src_rels is
    then empty through no fault of the destination's, so every entry in it looks
    like an orphan and the pass would empty the lot. rsync disables `--delete` on
    an I/O error for the same reason.
    """
    if ctx.root_unreadable:
        warn("not deleting anything: the source could not be listed, so nothing can be called an orphan of it.")
        return
    extras: list[tuple[str, bool]] = []
    _collect_extras_at(dst_fd, "", ctx, extras)
    targets = dict(extras)
    counter = [0, len(extras)]
    _remove_extras_at(dst_fd, "", targets, ctx, counter)
