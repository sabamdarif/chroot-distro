"""Filesystem operations addressed by directory descriptor.

Every walk here reaches an entry through openat(2) with O_NOFOLLOW off a pinned
directory fd, so no path this program did not validate is ever resolved twice.

Ported from proot-distro (https://github.com/termux/proot-distro), created by
Sylirre <sylirre@termux.dev> for the Termux project and licensed GPL-3.0, and
trimmed to what chroot-distro's `copy` and `sync` need.
"""

import contextlib
import errno
import os
import shutil
import stat
from collections.abc import Callable, Sequence
from typing import Any

_O_RD_DIR = os.O_RDONLY | os.O_DIRECTORY

_O_PATH_ANY = getattr(os, "O_PATH", 0) or os.O_RDONLY
_O_PATH_DIR = _O_PATH_ANY | os.O_DIRECTORY

REFUSED = frozenset((errno.ELOOP, errno.ENOTDIR))

TMP_SUFFIX = ".~cd_copy"

NAME_MAX = 255

_BUFSIZE = 256 * 1024
_ZERO_CHUNK = bytes(_BUFSIZE)
_MAX_EXTENTS = 1 << 20

_HAS_XATTR = hasattr(os, "listxattr")
_HAS_SEEK_HOLE = hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE")

_OnEntry = Callable[[str], None]
_OnError = Callable[[str, OSError], None]
_Frame = list[Any]


def is_refusal(exc: OSError) -> bool:
    """True when *exc* is an openat() refusing to follow a symlink.

    Linux reports ``O_NOFOLLOW|O_DIRECTORY`` on a symlink as ENOTDIR rather
    than ELOOP, so both errnos count as a refusal.
    """
    return exc.errno in REFUSED


def temp_name(name: str, suffix: str) -> str:
    """*name* with *suffix* appended, trimmed to fit in one path component.

    A name already at the filesystem's 255-byte limit turns the write into
    ENAMETOOLONG once a suffix is appended, so the stem is trimmed instead.
    The trim happens on the encoded bytes, since NAME_MAX counts those, and a
    multi-byte character cut in half comes back through os.fsdecode() as
    surrogates that re-encode to exactly the bytes it was cut to.
    """
    room = NAME_MAX - len(os.fsencode(suffix))
    encoded = os.fsencode(name)
    if len(encoded) <= room:
        return name + suffix
    return os.fsdecode(encoded[:room]) + suffix


def opendir_at(dir_fd: int, name: str) -> int:
    """Open subdirectory *name* under dir_fd, refusing a symlink."""
    return os.open(name, _O_RD_DIR | os.O_NOFOLLOW, dir_fd=dir_fd)


def reopen(dir_fd: int, name: str = "") -> int:
    """Return a readable directory fd for *name* under dir_fd.

    With no name, re-opens the directory dir_fd itself refers to. That is how
    a pin taken with O_PATH (which cannot be scanned) becomes something this
    module can walk, without going through /proc.
    """
    if name:
        return opendir_at(dir_fd, name)
    return os.open(os.curdir, _O_RD_DIR, dir_fd=dir_fd)


def opendir(path: str) -> int:
    """Open *path* as a directory. The caller owns the descriptor."""
    return os.open(path, _O_RD_DIR)


def descend_at(dir_fd: int, parts: Sequence[str], *, create: bool = False, mode: int | None = None) -> int:
    """Open the directory *parts* names under dir_fd. Descriptor, or raises.

    Each level is opened O_NOFOLLOW off the level above, so a component that is
    a symlink (ELOOP, or ENOTDIR for O_NOFOLLOW|O_DIRECTORY on Linux) or a
    plain file raises rather than being followed. A missing level raises
    FileNotFoundError unless create=True, which makes it with mkdirat off the
    same validated descriptor. *mode* is applied to the leaf through its
    descriptor.

    A caller that has pinned a directory keeps the guarantee that pin gives it
    only by descending from the descriptor: going back to the path re-resolves
    every component above, which is the part that was validated in the first
    place.

    dir_fd itself is left open; with no parts the answer is a fresh descriptor
    on the same directory, so the caller owns and closes what comes back either
    way.
    """
    fd: int | None = None
    try:
        for part in parts:
            src = dir_fd if fd is None else fd
            try:
                nxt = opendir_at(src, part)
            except FileNotFoundError:
                if not create:
                    raise
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o777, dir_fd=src)
                nxt = opendir_at(src, part)
            if fd is not None:
                os.close(fd)
            fd = nxt
        if fd is None:
            fd = reopen(dir_fd)
        if mode is not None:
            _chmod_fd(fd, mode)
        opened, fd = fd, None
        return opened
    finally:
        if fd is not None:
            os.close(fd)


def opendir_under(root: str, parts: Sequence[str], *, create: bool = False, mode: int | None = None) -> int | None:
    """Open the directory *parts* names under *root*. Descriptor, or None.

    The path form of descend_at(): the root is opened by name, everything
    below it is reached off a descriptor. What comes back names the inode the
    walk validated, so a caller that keeps addressing entries as
    (dir_fd, name) is proof against the directory being re-pointed afterwards.

    None means the directory is not reachable inside *root*: a component is a
    symlink or is not a directory, is missing (create=False), or the mkdir
    failed. The caller owns the returned descriptor and must close it.
    """
    try:
        root_fd = opendir(root)
    except OSError:
        return None
    try:
        return descend_at(root_fd, parts, create=create, mode=mode)
    except OSError:
        return None
    finally:
        os.close(root_fd)


def makedirs_under(root: str, parts: Sequence[str], mode: int | None = None) -> str | None:
    """Create the directory *parts* names under *root*. Path, or None.

    Every level is made with mkdirat off the descriptor of the level above and
    reopened with O_NOFOLLOW, so a component that is a symlink is refused
    instead of followed. os.makedirs() addresses each level by its path, so a
    link the image shipped -- or a guest planted -- sends the whole tree
    wherever it points, and the mode applied afterwards goes with it. That
    matters because these directories are made on the *host* side, with
    nothing confining the write.

    None means the directory could not be made inside *root*. Callers treat
    that as "do not use this path" rather than falling back to the name.

    *mode* is applied to the leaf through its descriptor, never through its
    name -- Linux has no AT_SYMLINK_NOFOLLOW for fchmodat(2), so a named chmod
    is the very hole this is closing.
    """
    fd = opendir_under(root, parts, create=True, mode=mode)
    if fd is None:
        return None
    os.close(fd)
    return os.path.join(root, *parts)


def open_file_at(dir_fd: int, name: str, flags: int, mode: int = 0o644) -> int:
    """Open the file *name* under dir_fd, never following a symlink."""
    return os.open(name, flags | os.O_NOFOLLOW, mode, dir_fd=dir_fd)


def open_regular_at(dir_fd: int, name: str, flags: int, mode: int = 0o644) -> tuple[int, os.stat_result]:
    """Open *name* under dir_fd as a regular file. Returns (fd, stat).

    O_NOFOLLOW keeps a planted symlink from being followed but says nothing
    about a named pipe, and opening one blocks until a peer appears — a peer a
    hostile guest simply never provides. O_NONBLOCK makes that open return
    instead, and the fstat that follows refuses every remaining type, so a
    device, a socket, or a pipe with a reader attached cannot be read or
    written either. The flag has no effect on a regular file, which is all
    that gets past here.
    """
    fd = open_file_at(dir_fd, name, flags | os.O_NONBLOCK, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", name)
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def open_new_at(dir_fd: int, name: str, mode: int = 0o644, *, readable: bool = False) -> tuple[int, os.stat_result]:
    """Create *name* under dir_fd as a brand-new file. Returns (fd, stat).

    O_EXCL, so no entry already carrying the name is ever written *through*.
    That is the one thing O_NOFOLLOW cannot give: a hardlink is
    indistinguishable from an ordinary file, and a guest that links a host
    file into its rootfs under the name a transfer is about to write leaves
    nothing to refuse. Creating a fresh inode keeps every write inside the
    directory the caller pinned.

    A leftover from an interrupted run is unlinked and the create retried
    once; unlinking removes the *name*, and whatever else the inode is linked
    from keeps its content.
    """
    access = os.O_RDWR if readable else os.O_WRONLY
    flags = access | os.O_CREAT | os.O_EXCL
    try:
        return open_regular_at(dir_fd, name, flags, mode)
    except FileExistsError:
        os.unlink(name, dir_fd=dir_fd)
        return open_regular_at(dir_fd, name, flags, mode)


def unlink_quietly(dir_fd: int, name: str) -> None:
    """Remove *name* under dir_fd, ignoring failure — for temp-file cleanup."""
    with contextlib.suppress(OSError):
        os.unlink(name, dir_fd=dir_fd)


def listdir_at(dir_fd: int) -> list[str]:
    """Return the sorted entry names of the directory dir_fd refers to."""
    with os.scandir(dir_fd) as it:
        return sorted(entry.name for entry in it)


def lstat_at(dir_fd: int, name: str) -> os.stat_result:
    """stat *name* under dir_fd without following a final symlink."""
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def exists_at(dir_fd: int, name: str) -> bool:
    """True when *name* exists under dir_fd, symlinks included."""
    try:
        lstat_at(dir_fd, name)
    except OSError:
        return False
    return True


def _copy_xattrs(src_fd: int, dst_fd: int) -> None:
    if not _HAS_XATTR:
        return
    try:
        names = os.listxattr(src_fd)
    except OSError:
        return
    for name in names:
        with contextlib.suppress(OSError):
            os.setxattr(dst_fd, name, os.getxattr(src_fd, name))


def copy_metadata(
    src_fd: int,
    dst_fd: int,
    src_st: os.stat_result | None = None,
    *,
    owner: tuple[int, int] | None = None,
) -> None:
    """Apply src's owner, mode, timestamps and xattrs to the open dst fd.

    shutil.copystat() expressed against file descriptors, plus the ownership it
    does not carry, so no path — and therefore no symlink — is involved.

    Ownership is numeric: a transfer runs as root and the two ends may name
    different users for the same id anyway, so the uid and gid are carried
    across as they stand rather than resolved through either side's passwd. It
    goes on before the mode, since chown(2) drops setuid and setgid whenever the
    caller lacks CAP_FSETID, which would silently disarm those bits on a
    destination the caller could not chmod back.

    *owner* is the pair `--chown` resolved on the destination side, used in place
    of the source's ids. Either half may be -1, which chown(2) reads as "leave
    this one as it is".

    Each step is best effort on its own: a destination filesystem may have no
    ownership to set (vfat, and so /sdcard) or no xattrs to hold, neither of
    which is a reason to abandon a transfer that has already written the data.
    """
    if src_st is None:
        src_st = os.fstat(src_fd)
    uid, gid = owner if owner is not None else (src_st.st_uid, src_st.st_gid)
    with contextlib.suppress(OSError):
        os.fchown(dst_fd, uid, gid)
    with contextlib.suppress(OSError):
        os.fchmod(dst_fd, stat.S_IMODE(src_st.st_mode))
    with contextlib.suppress(OSError):
        os.utime(dst_fd, ns=(src_st.st_atime_ns, src_st.st_mtime_ns))
    _copy_xattrs(src_fd, dst_fd)


def copy_link_metadata(
    dir_fd: int,
    name: str,
    src_st: os.stat_result | None = None,
    *,
    owner: tuple[int, int] | None = None,
) -> None:
    """Apply src_st's owner and timestamps to a symlink, never following it.

    A symlink has no mode of its own on Linux, so the two things worth carrying
    are the ones lchown(2) and utimensat(2) can set on the link itself. *owner*
    replaces the source's ids as it does in copy_metadata; with no src_st there
    are no timestamps to carry and only the owner is set.
    """
    if owner is None and src_st is not None:
        owner = (src_st.st_uid, src_st.st_gid)
    if owner is not None:
        with contextlib.suppress(OSError, NotImplementedError):
            os.chown(name, owner[0], owner[1], dir_fd=dir_fd, follow_symlinks=False)
    if src_st is not None:
        with contextlib.suppress(OSError, NotImplementedError):
            os.utime(
                name,
                ns=(src_st.st_atime_ns, src_st.st_mtime_ns),
                dir_fd=dir_fd,
                follow_symlinks=False,
            )


def _chmod_fd(fd: int, mode: int) -> bool:
    """Set *mode* on the inode *fd* refers to. True when it took.

    fchmod() covers an ordinary descriptor but fails with EBADF on an O_PATH
    one — and O_PATH is what paths.pin_path() hands out — so the fallback names
    the same descriptor through /proc, which works whatever the flags are.
    Both forms name a descriptor rather than a path, so neither can be
    redirected by a symlink appearing under the entry's name.
    """
    try:
        os.fchmod(fd, mode)
        return True
    except OSError:
        pass
    try:
        os.chmod(f"/proc/self/fd/{fd}", mode)
    except OSError:
        return False
    return True


def make_writable(dir_fd: int) -> None:
    """Add u+rwx to the directory dir_fd refers to, best effort."""
    try:
        st = os.fstat(dir_fd)
    except OSError:
        return
    _chmod_fd(dir_fd, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)


def chmod_at(dir_fd: int, name: str, mode: int, *, only_dir: bool = False) -> bool:
    """Set *mode* on *name* under dir_fd, best effort, never following a link.

    The mode is applied to a descriptor, never to the name: os.chmod() on the
    name follows a symlink (Linux has no AT_SYMLINK_NOFOLLOW for fchmodat), so
    an entry the caller lstat'ed as a directory and that a guest then replaced
    with a link would have its target chmod'ed. Opening O_PATH|O_NOFOLLOW
    refuses the link outright and needs no permission on the entry itself,
    which is usually the whole reason this is reached.

    O_PATH says nothing about the file *type*, so a caller that has already
    decided the entry is a directory passes only_dir=True to have the open
    refuse anything else as well.
    """
    flags = (_O_PATH_DIR if only_dir else _O_PATH_ANY) | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError:
        return False
    try:
        return _chmod_fd(fd, mode)
    finally:
        os.close(fd)


def _make_readable_at(dir_fd: int, name: str, mode: int) -> None:
    """Add u+rwx to the directory *name* under dir_fd, best effort."""
    chmod_at(dir_fd, name, mode, only_dir=True)


def _looks_sparse(st: os.stat_result) -> bool:
    """True when *st* describes a file stored in fewer blocks than its size.

    st_blocks counts 512-byte units whatever the filesystem's own block size
    is. A compressing filesystem reports fewer blocks for a file with no holes
    at all, which only costs the scan below — the copy is correct either way.
    """
    return st.st_blocks * 512 < st.st_size


def _write_all(fd: int, data: bytes, offset: int) -> None:
    """pwrite *data* at *offset*, which may take more than one call."""
    written = 0
    while written < len(data):
        written += os.pwrite(fd, data[written:], offset + written)


def _data_extents(fd: int, size: int) -> list[tuple[int, int]] | None:
    """Ask the filesystem where the file's data is. None when it will not say.

    SEEK_DATA / SEEK_HOLE give the hole map exactly, which reading cannot: a
    hole shorter than the copy buffer, or one not aligned to it, is
    indistinguishable from written zeros once read. Not every filesystem
    implements them — some fail outright, and the generic kernel fallback
    answers "it is all data" — so the caller checks the result against the
    file's length before trusting it.
    """
    if not _HAS_SEEK_HOLE:
        return None
    extents: list[tuple[int, int]] = []
    offset = 0
    try:
        while offset < size:
            try:
                start = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    break
                return None
            if start >= size:
                break
            end = os.lseek(fd, start, os.SEEK_HOLE)
            if end <= start:
                return None
            extents.append((start, min(end, size)))
            offset = end
            if len(extents) > _MAX_EXTENTS:
                return None
    except OSError:
        return None
    finally:
        os.lseek(fd, 0, os.SEEK_SET)
    return extents


def _copy_extents(src_fd: int, dst_fd: int, extents: list[tuple[int, int]], size: int) -> None:
    """Copy the ranges holding data, leaving the rest of the file a hole.

    Nothing is written past the last extent, so a file ending in a hole needs
    its length set explicitly.
    """
    for start, end in extents:
        pos = start
        while pos < end:
            chunk = os.pread(src_fd, min(_BUFSIZE, end - pos), pos)
            if not chunk:
                break
            _write_all(dst_fd, chunk, pos)
            pos += len(chunk)
    os.ftruncate(dst_fd, size)


def _copy_skipping_zeros(src_fd: int, dst_fd: int) -> None:
    """Copy a file, leaving a hole wherever a whole buffer reads back zero.

    The fallback for a filesystem that will not report its hole map. It can
    only find a hole as big as the copy buffer and aligned to it, so the result
    is sparse but not identically so; the content is exact either way.
    """
    pos = 0
    while True:
        chunk = os.pread(src_fd, _BUFSIZE, pos)
        if not chunk:
            break
        hole = chunk == _ZERO_CHUNK if len(chunk) == _BUFSIZE else chunk.count(b"\0") == len(chunk)
        if not hole:
            _write_all(dst_fd, chunk, pos)
        pos += len(chunk)
    os.ftruncate(dst_fd, pos)


def copy_data(src_fd: int, dst_fd: int, src_st: os.stat_result | None = None) -> None:
    """Copy the contents of one open file to another.

    Pass *src_st* to have a sparsely stored source copied hole for hole, so the
    destination takes the space the source actually occupied. Without it a
    rootfs's /var/log/lastlog — sparse, and nominally enormous because its
    length follows the highest uid on the system — is materialised in full.

    The hole map is taken from the filesystem when it will give one, and the
    extents are only believed when they account for less than the file's
    length: a filesystem with no support answers "it is all data", which is
    indistinguishable from a file that really is.
    """
    if src_st is not None and _looks_sparse(src_st):
        size = src_st.st_size
        extents = _data_extents(src_fd, size)
        if extents is not None and sum(e - s for s, e in extents) < size:
            _copy_extents(src_fd, dst_fd, extents, size)
        else:
            _copy_skipping_zeros(src_fd, dst_fd)
        return
    with open(src_fd, "rb", closefd=False) as fin, open(dst_fd, "wb", closefd=False) as fout:
        shutil.copyfileobj(fin, fout, _BUFSIZE)


def copy_file_at(
    src_dir_fd: int,
    src_name: str,
    dst_dir_fd: int,
    dst_name: str,
    src_st: os.stat_result | None = None,
    *,
    replace: bool = False,
    owner: tuple[int, int] | None = None,
) -> None:
    """Copy one regular file between two pinned directories.

    Both ends go through open_regular_at(), so neither a symlink nor a pipe
    planted at either name is followed, written through, or waited on, and the
    destination is always a new inode (see open_new_at) so neither is a
    hardlink.

    Pass replace=True when the destination may already exist — a copy onto a
    named file. The content then goes to a sibling temp file that is renamed
    into place, which also makes the write atomic: an interrupted copy leaves
    the old file rather than a truncated one. The cost is that a hardlinked
    destination loses its link, the unavoidable price of not being able to tell
    a guest's planted link from a legitimate one.

    A destination that is anything *but* a regular file is refused rather than
    replaced: the resolve already followed whatever link stood there, so one
    standing there now was planted since, and a pipe or a device is not
    something a copy has any business overwriting silently.

    Without replace the create is plain O_EXCL, which is all a fresh tree
    needs; merging into a tree that already exists passes replace=True.
    """
    sfd, sfd_st = open_regular_at(src_dir_fd, src_name, os.O_RDONLY)
    try:
        if src_st is None:
            src_st = sfd_st
        if replace:
            try:
                dst_st: os.stat_result | None = lstat_at(dst_dir_fd, dst_name)
            except OSError:
                dst_st = None
            if dst_st is not None and not stat.S_ISREG(dst_st.st_mode):
                raise OSError(errno.EEXIST, "destination exists and is not a regular file", dst_name)
        name = temp_name(dst_name, TMP_SUFFIX) if replace else dst_name
        try:
            dfd, _ = open_new_at(dst_dir_fd, name, stat.S_IMODE(src_st.st_mode))
            try:
                copy_data(sfd, dfd, sfd_st)
                copy_metadata(sfd, dfd, src_st, owner=owner)
            finally:
                os.close(dfd)
            if replace:
                os.replace(name, dst_name, src_dir_fd=dst_dir_fd, dst_dir_fd=dst_dir_fd)
        except BaseException:
            if replace:
                unlink_quietly(dst_dir_fd, name)
            raise
    finally:
        os.close(sfd)


def copy_symlink_at(
    src_dir_fd: int,
    src_name: str,
    dst_dir_fd: int,
    dst_name: str,
    src_st: os.stat_result | None = None,
    *,
    replace: bool = False,
    owner: tuple[int, int] | None = None,
) -> None:
    """Recreate a symlink at the destination, target verbatim.

    Pass replace=True when the destination name may already be taken —
    symlink(2) has no O_TRUNC and would only report EEXIST. The old name is
    unlinked first, which removes a *name* and never writes through what it
    held, so a hardlink to a file outside the container is not touched either.
    A directory standing there is left for the unlink to refuse, since emptying
    one is not this call's decision to make.
    """
    target = os.readlink(src_name, dir_fd=src_dir_fd)
    if replace:
        try:
            os.symlink(target, dst_name, dir_fd=dst_dir_fd)
        except FileExistsError:
            os.unlink(dst_name, dir_fd=dst_dir_fd)
            os.symlink(target, dst_name, dir_fd=dst_dir_fd)
    else:
        os.symlink(target, dst_name, dir_fd=dst_dir_fd)
    copy_link_metadata(dst_dir_fd, dst_name, src_st, owner=owner)


def close_frames(stack: list[_Frame]) -> None:
    """Close the fds an interrupted walk still holds, ignoring failures.

    Every walk that carries directories on an explicit stack lays its frames
    out the same way: the first two slots are the level's descriptors (the
    second None for a walk that needs only one), and the last is an `owned`
    flag, True for a level the walk opened for itself and False for the
    caller's fds, which stay open. A frame is pushed before its second
    descriptor is filled in, so that slot may still be None when an error lands
    between the two opens.
    """
    for frame in stack:
        if not frame[-1]:
            continue
        for fd in (frame[1], frame[0]):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)


MAX_OPEN_LEVELS = 64


def _dir_key(fd: int) -> tuple[int, int]:
    """(device, inode) of the directory *fd* refers to."""
    st = os.fstat(fd)
    return (st.st_dev, st.st_ino)


class Levels:
    """The directory levels of one walk, holding a bounded number of fds.

    A walk keeps its frames in the layout close_frames() describes and reads
    only the top of the stack, so every level between the root and the deepest
    few holds a descriptor open for nothing but the moment the walk climbs back
    through it. How deep a tree goes is guest or image content like everything
    else in one, and one fd per level meant an EMFILE partway down a few
    thousand levels — which a container can create in a second — against a soft
    limit of 1024 on Android and most distributions. So past
    MAX_OPEN_LEVELS live levels the shallowest is *parked*: its descriptors are
    closed and its identity kept, and it is reopened when the walk pops back
    down to it. Sixty-four is far past any real tree, so nothing ordinary ever
    parks a level.

    Reopening is `openat(child, "..")`, which the kernel answers from the
    directory's own parent link rather than by resolving a name, so nothing a
    guest plants can redirect it — but a directory it *moves* has a different
    parent, and a walk that followed one would leave the tree it was pointed
    at. Every level is therefore checked against the (device, inode) taken when
    it was parked, and one that does not match raises ESTALE.

    The top two levels are never parked: a walk that abandons a half-pushed
    frame resumes on the one below it, with no descendant left to reopen it
    through.

    Frames are the caller's own lists and are mutated in place, so
    close_frames() still unwinds an interrupted walk: a parked level carries
    None in both descriptor slots and has nothing left to close.
    """

    __slots__ = ("_budget", "_keys", "_low", "stack")

    def __init__(self, stack: list[_Frame], budget: int | None = None) -> None:
        self.stack = stack
        self._budget = MAX_OPEN_LEVELS if budget is None else budget
        self._keys: list[tuple[Any, ...] | None] = [None] * len(stack)
        self._low = 1

    def push(self, frame: _Frame) -> None:
        """Add a level, parking the shallowest ones beyond the budget."""
        self.stack.append(frame)
        self._keys.append(None)
        limit = len(self.stack) - 2
        while len(self.stack) - self._low > self._budget and self._low < limit:
            if not self._park(self._low):
                break
            self._low += 1

    def pop(self) -> _Frame:
        """Remove the top level, reviving the one below it. Returns it.

        The revived descriptors come through the popped level's own, so this
        must be called while it still holds them — before the walk does
        whatever it does with the level on the way out and closes them.
        """
        frame = self.stack.pop()
        self._keys.pop()
        if self.stack:
            keys = self._keys[-1]
            if keys is not None:
                _revive_level(self.stack[-1], keys, frame)
                self._keys[-1] = None
                self._low = len(self.stack) - 1
        return frame

    def truncate(self, depth: int) -> None:
        """Drop the levels from *depth* up, closing what they hold.

        For a walk that abandons a level it had only half opened. The level
        below is live by construction — see the class docstring — so nothing has
        to be revived through the frames being dropped.
        """
        close_frames(self.stack[depth:])
        del self.stack[depth:]
        del self._keys[depth:]

    def _park(self, index: int) -> bool:
        """Close a level's descriptors, keeping what it takes to reopen them.

        Both identities are taken before either descriptor is closed, so a
        level that cannot answer for itself is left as it was rather than half
        parked, which would leave the walk holding one descriptor of a level it
        can no longer reopen.
        """
        frame = self.stack[index]
        keys: list[tuple[int, int] | None] = []
        for slot in (0, 1):
            fd = frame[slot]
            if fd is None:
                keys.append(None)
                continue
            try:
                keys.append(_dir_key(fd))
            except OSError:
                return False
        for slot in (0, 1):
            fd = frame[slot]
            if fd is None:
                continue
            frame[slot] = None
            with contextlib.suppress(OSError):
                os.close(fd)
        self._keys[index] = tuple(keys)
        return True


def _revive_level(frame: _Frame, keys: tuple[Any, ...], child: _Frame) -> None:
    """Reopen a parked level's descriptors through *child*'s."""
    for slot in (0, 1):
        key = keys[slot]
        if key is None:
            continue
        below = child[slot]
        if below is None:
            raise OSError(errno.ESTALE, "the level below was closed before this one")
        up = os.open(os.pardir, _O_RD_DIR | os.O_NOFOLLOW, dir_fd=below)
        try:
            if _dir_key(up) != key:
                raise OSError(errno.ESTALE, "a directory was moved while the walk was inside it")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(up)
            raise
        frame[slot] = up


def count_tree_at(dir_fd: int) -> int:
    """Count the files, symlinks and special entries under dir_fd.

    A cheap first pass so a copy can show progress against a total, the way
    `sync` does. Directories are descended into but not counted: copy_tree_at
    reports an entry once it has *written* one, which for a directory is only
    true after its contents are in, so counting them would leave the bar short
    of the end by the number of directories. Anything unreadable counts as
    nothing and is left for the copy itself to report.

    Frame layout: [fd, None, pending names, owned].
    """
    total = 0
    stack: list[_Frame] = [[dir_fd, None, None, False]]
    levels = Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, pending, owned = frame
            if pending is None:
                try:
                    pending = frame[2] = listdir_at(fd)
                except OSError:
                    pending = frame[2] = []
            if not pending:
                levels.pop()
                if owned:
                    os.close(fd)
                continue
            name = pending.pop()
            try:
                if not stat.S_ISDIR(lstat_at(fd, name).st_mode):
                    total += 1
                    continue
                sub = opendir_at(fd, name)
            except OSError:
                total += 1
                continue
            levels.push([sub, None, None, True])
    except BaseException:
        close_frames(stack)
        raise
    return total


def copy_tree_at(
    src_dir_fd: int,
    dst_dir_fd: int,
    *,
    rel: str = "",
    merge: bool = False,
    owner: tuple[int, int] | None = None,
    on_entry: _OnEntry | None = None,
    on_skip: _OnEntry | None = None,
    on_error: _OnError | None = None,
) -> None:
    """Recursively copy the contents of one directory into another.

    Mirrors shutil.copytree(symlinks=True): symlinks are recreated as symlinks
    and never descended into, and modes and timestamps are preserved. Unlike
    copytree, a device/FIFO/socket is reported to on_skip and left out rather
    than aborting the whole transfer.

    With merge=True an entry the destination already holds is written over
    rather than refused, which is what `cp -a` does and what a second run of the
    same copy needs: a directory already there is descended into instead of
    ending the entry on mkdir's EEXIST, a file is replaced through the
    temp-and-rename path (see copy_file_at), and a symlink is unlinked and
    recreated. A destination whose *type* disagrees with the source's is still
    refused and reported. Without merge every create is exclusive, which is what
    a move's cross-device fallback wants: rename(2) would not have overwritten a
    populated directory either.

    *owner* is `--chown`'s resolved pair, applied to every entry written in place
    of the ids the source carries.

    on_entry(rel_path) is called for each file and symlink written.

    on_error(rel_path, exc) is called for an entry that could not be copied,
    which is then stepped over: one unreadable file or directory in a tree must
    not end the transfer, since the point of the command is usually to save what
    *can* be saved. A caller with no on_error still gets the exception.

    The descent is an explicit stack rather than recursion. How deep a tree goes
    is the guest's to decide, and a thousand nested directories would exhaust
    the interpreter's own stack and end the command in a traceback, since
    RecursionError is not an OSError and no caller's net catches it.

    A directory is created writable and sealed on the way back up: mkdir's mode
    is masked by the umask and so cannot preserve the source mode on its own,
    and applying it any earlier would have a source directory that is not
    writable itself (0555 and friends) reject its own contents.

    Frame layout: [src_fd, dst_fd, rel, pending names, src_st, owned]. src_st is
    the source directory's lstat, applied to the destination once that level's
    contents are in; the caller's frame carries None for it and owns its own fds
    (see close_frames).
    """
    stack: list[_Frame] = [[src_dir_fd, dst_dir_fd, rel, None, None, False]]
    levels = Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            src_fd, dst_fd, cur, pending, dir_st, owned = frame
            if pending is None:
                try:
                    pending = frame[3] = listdir_at(src_fd)
                except OSError as exc:
                    if on_error is None:
                        raise
                    on_error(cur, exc)
                    pending = frame[3] = []
                pending.reverse()
            if not pending:
                levels.pop()
                if owned:
                    try:
                        copy_metadata(src_fd, dst_fd, dir_st, owner=owner)
                    finally:
                        os.close(dst_fd)
                        os.close(src_fd)
                continue

            name = pending.pop()
            child = f"{cur}/{name}" if cur else name
            depth = len(stack)
            try:
                src_st = lstat_at(src_fd, name)
                mode = src_st.st_mode

                if stat.S_ISLNK(mode):
                    copy_symlink_at(src_fd, name, dst_fd, name, src_st, replace=merge, owner=owner)
                    if on_entry:
                        on_entry(child)
                elif stat.S_ISDIR(mode):
                    fresh = True
                    try:
                        os.mkdir(name, 0o700, dir_fd=dst_fd)
                    except FileExistsError:
                        if not merge:
                            raise
                        fresh = False
                    sub_src = opendir_at(src_fd, name)
                    levels.push([sub_src, None, child, None, src_st, True])
                    sub_dst = stack[-1][1] = opendir_at(dst_fd, name)
                    if not fresh:
                        make_writable(sub_dst)
                elif stat.S_ISREG(mode):
                    copy_file_at(src_fd, name, dst_fd, name, src_st, replace=merge, owner=owner)
                    if on_entry:
                        on_entry(child)
                elif on_skip:
                    on_skip(child)
            except OSError as exc:
                if on_error is None:
                    raise
                if len(stack) > depth:
                    levels.truncate(depth)
                on_error(child, exc)
    except BaseException:
        close_frames(stack)
        raise


def _chown_reporting(dir_fd: int, name: str, rel: str, uid: int, gid: int, on_error: _OnError | None) -> None:
    """lchown one entry, handing a refusal to *on_error* if there is one."""
    try:
        os.chown(name, uid, gid, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        if on_error is None:
            raise
        on_error(rel, exc)


def chown_tree_at(
    dir_fd: int,
    name: str,
    owner: tuple[int, int],
    *,
    on_error: _OnError | None = None,
) -> None:
    """Set *owner* on *name* and everything below it.

    What `--chown` needs after a move rename(2) carried out by itself: the
    entries keep their inodes, and with them the ids they had on the source side,
    so the only way the flag can reach them is a walk of its own afterwards.

    Every id is set with lchown(2), so a symlink is given the owner rather than
    whatever it points at, and each level is descended through opendir_at, which
    refuses a symlink outright — the walk cannot leave the tree it was handed.
    The descent is an explicit stack for the reason copy_tree_at's is: how deep
    the tree goes is not this code's decision.

    on_error(rel, exc) is called for an entry that would not take the owner,
    which is then stepped over; without one the exception stands. rel names the
    entry relative to *name*, "" for the root itself.

    Frame layout: [fd, None, rel, pending names, owned].
    """
    uid, gid = owner
    _chown_reporting(dir_fd, name, "", uid, gid, on_error)
    try:
        if not stat.S_ISDIR(lstat_at(dir_fd, name).st_mode):
            return
        root_fd = opendir_at(dir_fd, name)
    except OSError as exc:
        if on_error is None:
            raise
        on_error("", exc)
        return

    stack: list[_Frame] = [[root_fd, None, "", None, True]]
    levels = Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, cur, pending, owned = frame
            if pending is None:
                try:
                    pending = frame[3] = listdir_at(fd)
                except OSError as exc:
                    if on_error is None:
                        raise
                    on_error(cur, exc)
                    pending = frame[3] = []
                pending.reverse()
            if not pending:
                levels.pop()
                if owned:
                    os.close(fd)
                continue

            child = pending.pop()
            child_rel = f"{cur}/{child}" if cur else child
            _chown_reporting(fd, child, child_rel, uid, gid, on_error)
            try:
                if not stat.S_ISDIR(lstat_at(fd, child).st_mode):
                    continue
                sub = opendir_at(fd, child)
            except OSError as exc:
                if on_error is None:
                    raise
                on_error(child_rel, exc)
                continue
            levels.push([sub, None, child_rel, None, True])
    except BaseException:
        close_frames(stack)
        raise


def _unlink_at(dir_fd: int, name: str, is_dir: bool, force: bool) -> None:
    """Remove *name* under dir_fd, relaxing the containing directory on EPERM.

    Only the *containing* directory's mode governs an unlink; the entry's own is
    irrelevant, so there is nothing to relax on it.
    """
    try:
        if is_dir:
            os.rmdir(name, dir_fd=dir_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)
        return
    except PermissionError:
        if not force:
            raise
    make_writable(dir_fd)
    if is_dir:
        os.rmdir(name, dir_fd=dir_fd)
    else:
        os.unlink(name, dir_fd=dir_fd)


def _opendir_for_removal(dir_fd: int, name: str, st: os.stat_result, force: bool) -> int:
    """Open the directory *name* under dir_fd so its contents can go.

    When the descent is refused and *force* is set, the entry itself is made
    readable — through a descriptor, not through its name, see _make_readable_at.
    """
    try:
        return opendir_at(dir_fd, name)
    except PermissionError:
        if not force:
            raise
        _make_readable_at(dir_fd, name, stat.S_IMODE(st.st_mode) | stat.S_IRWXU)
        return opendir_at(dir_fd, name)


def _removal_failed(rel: str, exc: OSError, on_error: _OnError | None) -> None:
    """Report *exc* against *rel*, or re-raise when nobody is listening."""
    if on_error is None:
        raise exc
    on_error(rel, exc)


def _unlink_reporting(
    dir_fd: int,
    name: str,
    rel: str,
    force: bool,
    on_error: _OnError | None,
    on_remove: _OnEntry | None,
) -> bool:
    """Unlink one non-directory, reporting through the walk's callbacks."""
    try:
        _unlink_at(dir_fd, name, False, force)
    except FileNotFoundError:
        return True
    except OSError as exc:
        _removal_failed(rel, exc, on_error)
        return False
    if on_remove is not None:
        on_remove(rel)
    return True


def rmtree_at(
    dir_fd: int,
    name: str,
    *,
    force: bool = False,
    on_error: _OnError | None = None,
    on_remove: _OnEntry | None = None,
) -> bool:
    """Remove *name* under dir_fd, descending without following symlinks.

    A symlink is unlinked, never traversed, so this cannot reach outside the
    tree it was pointed at. With force=True an unwritable directory is chmod'ed
    and retried, which is what `sync --delete` needs.

    The descent is an explicit stack for the reason copy_tree_at's is: the tree
    is guest content, and one deeper than the interpreter's recursion limit
    would end the command in a traceback rather than a message.

    on_error(rel, exc) is called for an entry that would not go, which is then
    stepped over so the rest of the tree still goes. A caller with no on_error
    still gets the exception, and the walk stops where it stands. on_remove(rel)
    is called for each entry that did go. Both name the entry relative to
    *name*, which is "" for the root itself.

    Returns True when nothing of the tree is left. A directory whose contents did
    not all go is not rmdir'ed — the ENOTEMPTY that would follow says nothing the
    failure below it has not already said.

    Frame layout: [fd, None, own name, own rel, pending, emptied, owned]. The two
    descriptor slots come first and `owned` last so close_frames() unwinds an
    interrupted walk; `emptied` stays True only while everything below the level
    has gone, and it is what decides whether the level itself may be rmdir'ed.
    The directory a level is removed *from* is the level below it, taken from the
    stack rather than kept in the frame: a parked level has closed its
    descriptors, so a copy of one made on the way down would name a closed fd —
    or, once the number is reused, some other file entirely.
    """
    try:
        st = lstat_at(dir_fd, name)
    except FileNotFoundError:
        return True
    except OSError as exc:
        _removal_failed("", exc, on_error)
        return False

    if not stat.S_ISDIR(st.st_mode):
        return _unlink_reporting(dir_fd, name, "", force, on_error, on_remove)

    try:
        root_fd = _opendir_for_removal(dir_fd, name, st, force)
    except OSError as exc:
        _removal_failed("", exc, on_error)
        return False

    ok = True
    stack: list[_Frame] = [[root_fd, None, name, "", None, True, True]]
    levels = Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, entry, rel, pending, _, _ = frame
            if pending is None:
                try:
                    pending = listdir_at(fd)
                except OSError as exc:
                    _removal_failed(rel, exc, on_error)
                    pending, frame[5] = [], False
                pending.reverse()
                frame[4] = pending

            if not pending:
                try:
                    levels.pop()
                except OSError as exc:
                    os.close(fd)
                    _removal_failed(rel, exc, on_error)
                    close_frames(stack)
                    del stack[:]
                    return False
                parent_fd = stack[-1][0] if stack else dir_fd
                os.close(fd)
                if frame[5]:
                    try:
                        _unlink_at(parent_fd, entry, True, force)
                    except OSError as exc:
                        _removal_failed(rel, exc, on_error)
                        frame[5] = False
                    else:
                        if on_remove is not None:
                            on_remove(rel)
                if not frame[5]:
                    ok = False
                    if stack:
                        stack[-1][5] = False
                continue

            child = pending.pop()
            child_rel = f"{rel}/{child}" if rel else child
            try:
                child_st = lstat_at(fd, child)
            except FileNotFoundError:
                continue
            except OSError as exc:
                _removal_failed(child_rel, exc, on_error)
                frame[5] = False
                continue

            if not stat.S_ISDIR(child_st.st_mode):
                if not _unlink_reporting(fd, child, child_rel, force, on_error, on_remove):
                    frame[5] = False
                continue

            try:
                sub = _opendir_for_removal(fd, child, child_st, force)
            except OSError as exc:
                _removal_failed(child_rel, exc, on_error)
                frame[5] = False
                continue
            levels.push([sub, None, child, child_rel, None, True, True])
    except BaseException:
        close_frames(stack)
        raise

    return ok
