# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Copy and move files between host paths and installed containers.

Endpoints are `[container:]path` specs. A recursive copy recreates a directory
tree the way `cp -a` does (numeric ownership, modes and timestamps carried
across, symlinks preserved as symlinks, a sparsely stored file written back
sparsely, hardlinks turned into independent copies), and it
merges into a destination tree that is already there, so running the same copy
twice updates it instead of stopping on the first mkdir's EEXIST. `--move` keeps
rename(2)'s rule instead and refuses a populated destination directory.

Every filesystem call goes through a descriptor pinned by `paths.pin_path`, so
no component of either endpoint is resolved a second time and a symlink planted
mid-transfer cannot redirect a write out of the container. An entry that cannot
be read is reported and stepped over rather than ending the transfer, which is
`cp -r`'s behaviour; the command then exits non-zero, and `--move` leaves the
source in place because the copy it would be deleting is incomplete, including
when the only thing missing is a device, FIFO or socket, which no tree this
module writes carries across.

Ported from proot-distro (https://github.com/termux/proot-distro), created by
Sylirre <sylirre@termux.dev> for the Termux project and licensed GPL-3.0, then
adapted to chroot-distro's message helpers and path resolution.
"""

import errno
import os
import stat
import sys
from contextlib import ExitStack

from chroot_distro import dirfd
from chroot_distro.helpers.owner import resolve_owner
from chroot_distro.message import crit_error, log_error, log_info, quote_path, warn
from chroot_distro.paths import (
    PinnedPath,
    container_locks_for_spec_pair,
    pin_path,
    refuse_src_dest_overlap,
    resolve_container_child,
    resolve_container_path,
)
from chroot_distro.progress import clear_bar, draw_count_bar, progress_active


def command_copy(args) -> None:
    """Copy or move files between host paths and container paths."""
    src = args.source
    dest = args.destination
    verbose = getattr(args, "verbose", False)
    move_mode = getattr(args, "move", False)
    recursive = getattr(args, "recursive", False)
    chown = getattr(args, "chown", None)

    with ExitStack() as stack:
        for lock in container_locks_for_spec_pair(src, dest, command="copy"):
            stack.enter_context(lock)
        _do_copy(src, dest, verbose, move_mode, recursive, chown)


def _copy_tree_pinned(
    src_pin: PinnedPath,
    dest_pin: PinnedPath,
    verbose: bool,
    dest_display: str,
    *,
    merge: bool = False,
    owner: tuple[int, int] | None = None,
) -> tuple[int, int]:
    """Recreate the source directory under the destination, fd by fd.

    Replaces shutil.copytree(symlinks=True). copytree walks by path, so every
    directory it creates and descends into is addressed by name and can be
    swapped for a symlink mid-transfer; carrying the fds down the walk removes
    that entirely.

    Returns (failures, skipped): entries that could not be copied, and
    device/FIFO/socket entries deliberately left out. Both are reported one by
    one and stepped over rather than ending the transfer (see
    dirfd.copy_tree_at), so the caller has to ask: `--move` in particular must
    remove nothing when either count is non-zero, since the source then holds
    the only copy of whatever did not make it across.

    merge=True lets the walk write into a destination tree that already exists.
    `--move`'s cross-device fallback leaves it off so that it refuses a
    populated destination directory, which is what the rename(2) it stands in
    for would have done. Without merge the mkdir declines to create over
    anything already at the name, a planted symlink included.

    The destination directory is created writable and sealed with the source's
    mode once its contents are in, since mkdir's mode is masked by the umask and
    a source directory that is not writable itself (0555 and friends) would
    otherwise reject its own contents. The fd-relative calls know only the leaf
    name, so failures naming the destination are re-raised carrying
    *dest_display*; a failure to *read* is named on the source side instead,
    because pointing at a destination that was never written reads as the wrong
    fault.
    """
    failures = [0]
    skipped = [0]
    src_fd = dirfd.reopen(src_pin.dir_fd, src_pin.leaf)
    try:
        src_st = os.fstat(src_fd)
        try:
            os.mkdir(dest_pin.leaf, 0o700, dir_fd=dest_pin.dir_fd)
        except FileExistsError:
            if not merge:
                raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), dest_display) from None
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror, dest_display) from None
        try:
            dst_fd = dirfd.opendir_at(dest_pin.dir_fd, dest_pin.leaf)
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror, dest_display) from None
        try:
            dirfd.make_writable(dst_fd)

            def shown(rel: str) -> str:
                return quote_path(os.path.join(dest_display, rel))

            def src_shown(rel: str) -> str:
                return quote_path(os.path.join(str(src_pin), rel) if rel else str(src_pin))

            total = 0 if verbose or not progress_active() else dirfd.count_tree_at(src_fd)
            done = [0]

            def on_entry(rel: str) -> None:
                done[0] += 1
                if verbose:
                    log_info(f"Copying: '{shown(rel)}'")
                elif total:
                    draw_count_bar(done[0], total, unit="entries")

            def on_skip(rel: str) -> None:
                done[0] += 1
                skipped[0] += 1
                warn(f"skipping special file '{shown(rel)}'.")

            def on_error(rel: str, exc: OSError) -> None:
                failures[0] += 1
                done[0] += 1
                warn(f"cannot copy '{src_shown(rel)}': {quote_path(exc.strerror or str(exc))}.")

            dirfd.copy_tree_at(
                src_fd,
                dst_fd,
                merge=merge,
                owner=owner,
                on_entry=on_entry,
                on_skip=on_skip,
                on_error=on_error,
            )
            dirfd.copy_metadata(src_fd, dst_fd, src_st, owner=owner)
        finally:
            clear_bar()
            os.close(dst_fd)
    finally:
        os.close(src_fd)
    return failures[0], skipped[0]


def _apply_owner_after_rename(dest_pin: PinnedPath, owner: tuple[int, int]) -> None:
    """Give the moved entry the requested owner, reporting a refusal once.

    A rename keeps the inodes and the ids they came with, so `--chown` has to
    walk the destination afterwards. A filesystem that holds no ownership (vfat,
    and so /sdcard) refuses every entry in the tree, which is worth saying once
    and not once per file.
    """
    refused: list[OSError] = []
    dirfd.chown_tree_at(
        dest_pin.dir_fd,
        dest_pin.leaf,
        owner,
        on_error=lambda _rel, exc: refused.append(exc),
    )
    if refused:
        plural = "entry" if len(refused) == 1 else "entries"
        warn(
            f"moved, but {len(refused)} {plural} under '{quote_path(str(dest_pin))}' "
            f"would not take the requested owner: {quote_path(refused[0].strerror or str(refused[0]))}."
        )


def _move_pinned(
    src_pin: PinnedPath,
    dest_pin: PinnedPath,
    verbose: bool = False,
    owner: tuple[int, int] | None = None,
) -> int:
    """Move via renameat, falling back to copy+remove across devices.

    rename(2) replaces a symlink sitting at the destination rather than
    following it, and both ends are named relative to a pinned fd, so the fast
    path needs no further protection.

    Across devices the move becomes copy + remove. The entry's type comes from
    the pinned fd rather than the caller's earlier path probe, so a symlink is
    recognised as one and recreated verbatim, never followed. Off the fast path
    the destination name also has to be cleared by hand: writing into a name
    that is still there could go through a hardlink to a file outside the
    container, and os.symlink() would simply refuse with EEXIST. A directory
    source is left to _copy_tree_pinned, whose mkdir declines to overwrite
    anything, as rename(2) declines a non-empty or non-directory target.

    `--chown` reaches the fast path through _apply_owner_after_rename, since a
    rename writes nothing and so has no moment at which an owner could be set;
    the fallback carries the pair into the copy calls like any other transfer.

    Returns the number of entries the fallback did not carry across. Nothing is
    removed from the source when that is non-zero: a move whose copy half
    skipped an entry would otherwise delete the only copy of it. Entries skipped
    *by design* count here too: a device, FIFO or socket is left out of every
    tree this module writes, which is a warning during a copy but silent data
    loss during a move, and on Termux the common move (a rootfs onto /sdcard) is
    exactly the cross-device one.
    """
    try:
        os.rename(src_pin.leaf, dest_pin.leaf, src_dir_fd=src_pin.dir_fd, dst_dir_fd=dest_pin.dir_fd)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    else:
        if owner is not None:
            _apply_owner_after_rename(dest_pin, owner)
        return 0

    src_st = dirfd.lstat_at(src_pin.dir_fd, src_pin.leaf)

    if not stat.S_ISDIR(src_st.st_mode):
        dirfd.unlink_quietly(dest_pin.dir_fd, dest_pin.leaf)

    if stat.S_ISLNK(src_st.st_mode):
        dirfd.copy_symlink_at(src_pin.dir_fd, src_pin.leaf, dest_pin.dir_fd, dest_pin.leaf, src_st, owner=owner)
        os.unlink(src_pin.leaf, dir_fd=src_pin.dir_fd)
    elif stat.S_ISDIR(src_st.st_mode):
        failures, skipped = _copy_tree_pinned(src_pin, dest_pin, verbose, str(dest_pin), owner=owner)
        if failures or skipped:
            log_error("Source left in place: the copy did not complete.")
            return failures + skipped
        dirfd.rmtree_at(src_pin.dir_fd, src_pin.leaf, force=True)
    else:
        dirfd.copy_file_at(src_pin.dir_fd, src_pin.leaf, dest_pin.dir_fd, dest_pin.leaf, owner=owner)
        os.unlink(src_pin.leaf, dir_fd=src_pin.dir_fd)
    return 0


def _do_copy(src: str, dest: str, verbose: bool, move_mode: bool, recursive: bool, chown: str | None = None) -> None:
    """Resolve both endpoints, pin them, and run the copy or the move.

    A move acts on the entries themselves, so neither final component is
    dereferenced: rename(2) moves a symlink rather than what it points at, and
    replaces one sitting at the destination rather than writing through it, which
    is what mv does. A plain copy keeps cp's semantics and follows both. For the
    same reason the existence probe is lexists() in move mode (a dangling
    symlink is a perfectly good thing to move), and the readability probe is
    skipped for a symlink source, since nothing reads it and testing the target
    would reject a dangling or unreadable one for no reason.

    A device, FIFO or socket named as the source is refused here for a clear
    message; dirfd.open_regular_at() refuses it again on the pinned fd, which is
    what covers one planted after this check and what keeps the open from
    blocking on a pipe with no writer. Whether the source is a directory comes
    from that same lstat rather than os.path.isdir(), which in move mode would
    resolve a *container* link against the host filesystem.

    Anything copied or moved onto an existing directory lands inside it, as cp
    and mv both do. The source's base name is appended through the resolver
    rather than joined on, because it is a path component inside the container
    like any other and may itself be a symlink; mv moves inside the directory a
    destination *link* points at while leaving the link in place, so the question
    is asked of the target while dest_path keeps the name rename(2) acts on. Once
    both ends are final, the earliest point at which a planted symlink can no
    longer hide that they overlap, the overlap guard runs.

    Both endpoints are then pinned and the filesystem is addressed only through
    the pinned fds. The destination's missing parents are created by that same
    walk (create=True); making them by path first would write through a symlink
    planted after the resolve, before the pin could refuse.
    """
    src_path = resolve_container_path(src, deref_leaf=not move_mode)
    dest_path = resolve_container_path(dest, deref_leaf=not move_mode)
    owner = resolve_owner(chown, dest) if chown else None

    if not (os.path.lexists(src_path) if move_mode else os.path.exists(src_path)):
        crit_error(f"cannot copy '{src}' because the path does not exist.")
        sys.exit(1)

    try:
        src_mode = os.lstat(src_path).st_mode
    except OSError as exc:
        crit_error(f"cannot copy '{src}': {exc.strerror}.")
        sys.exit(1)

    if not (stat.S_ISREG(src_mode) or stat.S_ISDIR(src_mode) or stat.S_ISLNK(src_mode)):
        crit_error(f"cannot copy '{src}': not a regular file or directory.")
        sys.exit(1)

    if not stat.S_ISLNK(src_mode) and not os.access(src_path, os.R_OK):
        crit_error(f"source path '{quote_path(src_path)}' is not readable.")
        sys.exit(1)

    src_is_dir = stat.S_ISDIR(src_mode)
    if src_is_dir and not recursive and not move_mode:
        crit_error("source path is a directory. Use option '--recursive' to copy directories.")
        sys.exit(1)

    dest_target = resolve_container_path(dest) if move_mode else dest_path
    if os.path.isdir(dest_target):
        dest_path = resolve_container_child(dest, dest_target, os.path.basename(src_path), deref_leaf=not move_mode)

    refuse_src_dest_overlap(src, src_path, dest, dest_path, deref_leaf=not move_mode)

    log_info(f"Source: '{quote_path(src_path)}'")
    log_info(f"Destination: '{quote_path(dest_path)}'")

    dest_dir = os.path.dirname(dest_path)
    if not os.path.isdir(dest_dir):
        log_info(f"Creating directory '{quote_path(dest_dir)}'...")

    failures = 0
    try:
        with ExitStack() as pins:
            src_pin = pins.enter_context(pin_path(src, src_path))
            dest_pin = pins.enter_context(pin_path(dest, dest_path, create=True))

            if move_mode:
                log_info("Moving files...")
                if verbose:
                    log_info(f"Moving: '{quote_path(src_path)}' -> '{quote_path(dest_path)}'")
                failures = _move_pinned(src_pin, dest_pin, verbose, owner)
            elif src_is_dir:
                log_info("Copying files, this may take a while...")
                failures, _ = _copy_tree_pinned(src_pin, dest_pin, verbose, dest_path, merge=True, owner=owner)
            else:
                log_info("Copying files, this may take a while...")
                if verbose:
                    log_info(f"Copying: '{quote_path(src_path)}' -> '{quote_path(dest_path)}'")
                dirfd.copy_file_at(
                    src_pin.dir_fd, src_pin.leaf, dest_pin.dir_fd, dest_pin.leaf, replace=True, owner=owner
                )
    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        sys.exit(1)
    except OSError as exc:
        clear_bar()
        crit_error(quote_path(str(exc)))
        sys.exit(1)

    if failures:
        plural = "entry" if failures == 1 else "entries"
        crit_error(f"{failures} {plural} could not be copied.")
        sys.exit(1)

    log_info("Finished copying files.")
