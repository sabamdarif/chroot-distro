"""Write a file by staging a sibling temporary and renaming it into place.

The pattern lives in every cache, manifest, layer and state-file writer here, so
it is centralised: one place resolves the destination directory, mints a
process-unique temporary name so two concurrent writers cannot collide, and
removes the temporary when the block exits unsuccessfully -- KeyboardInterrupt
included, so a Ctrl-C never publishes half a file.

A destination inside this program's own state directories is reached through a
descriptor. `os.makedirs(exist_ok=True)` accepts a symlink to a directory and
`tempfile.mkstemp(dir=...)` then resolves the same name again, so a guest that
leaves `cache/oci_layers -> <host dir>` behind has every blob written into that
host directory and renamed into place there. RUNTIME_DIR and BASE_CACHE_DIR are
guest-writable on Termux, where both sit under the $TERMUX_PREFIX bound
read-write into every non-isolated container. The components below whichever
root contains the destination are therefore walked one at a time with
O_NOFOLLOW, the temporary is created O_EXCL off the descriptor that walk
validated, and the publishing rename runs `src_dir_fd`/`dst_dir_fd` on it. The
final `os.replace` was never the hole -- rename(2) follows no symlink at either
end -- the parents were.

A path outside those roots is the user's own (`backup -o`, `build --output`) and
keeps the plain behaviour: where the user points it is not this program's
business.

`publish_file` is the same ending without the beginning, for a writer whose
final name cannot be known until its bytes exist -- a build's layer blob is named
by the digest of its own content, so it is packed into the build's scratch
directory and renamed into the cache afterwards. The destination directory is
reached the same way.

The temporary's *path* is still what `atomic_replace`'s caller writes through,
since it opens the file itself. That name is unpredictable and was just created,
so nothing can be waiting under it, and a directory re-pointed in the window
between strands those bytes under a random name and fails the rename rather than
publishing them somewhere else.

Ported from proot-distro (https://github.com/termux/proot-distro), created by
Sylirre <sylirre@termux.dev> for the Termux project and licensed GPL-3.0, and
adapted to this project's two writers and their `mode=` handling.
"""

import contextlib
import errno
import os
import sys
import tempfile
import typing
from collections.abc import Iterator

from chroot_distro import dirfd
from chroot_distro.constants import BASE_CACHE_DIR, RUNTIME_DIR

# Shortest first: on Termux BASE_CACHE_DIR lives *under* RUNTIME_DIR, so
# matching the outer root is what puts `cache` itself inside the walk rather
# than in the part taken on trust. Off Termux the two are unrelated (XDG data
# vs cache) and at most one of them ever matches.
_STATE_ROOTS = tuple(sorted({RUNTIME_DIR, BASE_CACHE_DIR}, key=len))


def _fsync_directory(dir_path: str) -> None:
    """Fsync a directory to ensure rename/link metadata reaches disk."""
    if sys.platform != "win32":
        fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _state_location(path: str) -> tuple[str | None, tuple[str, ...]]:
    """Return (root, parts) when *path* is inside a state directory, else (None, ())."""
    for root in _STATE_ROOTS:
        prefix = root.rstrip(os.sep) + os.sep
        if path.startswith(prefix):
            parts = tuple(part for part in path[len(prefix) :].split(os.sep) if part)
            if parts:
                return root, parts
    return None, ()


def _open_dest_dir(path: str) -> int | None:
    """Open the directory *path* is published in, or None for the user's own path.

    The root is created by name, since it is this program's to create; every
    component below it is walked with O_NOFOLLOW and made off the descriptor
    above. One that is not a plain directory raises ENOTDIR rather than being
    followed, which every caller already treats as a failed write.
    """
    root, parts = _state_location(path)
    if root is None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        return None
    with contextlib.suppress(OSError):
        os.makedirs(root, exist_ok=True)
    dir_fd = dirfd.opendir_under(root, parts[:-1], create=True)
    if dir_fd is None:
        raise OSError(errno.ENOTDIR, "not a directory inside the state tree", os.path.dirname(path))
    return dir_fd


def publish_file(src_path: str, dest_path: str) -> None:
    """Rename an already-written file onto *dest_path*.

    For a writer that cannot name its destination up front: a layer blob is
    named by the digest of its own bytes, so a build packs it into its scratch
    directory and publishes it once the digest is known. Spelled by hand that was
    `os.makedirs(os.path.dirname(dest))` followed by `os.replace(tmp, dest)`,
    which resolved the destination directory by name twice, so a guest that left
    `cache/oci_layers -> <host dir>` behind collected every layer a build
    produced. The directory is walked down to instead and the rename runs
    `dst_dir_fd` on the descriptor that walk validated. rename(2) follows no
    symlink at the destination name either, so a link planted *as* the blob is
    replaced rather than written through.

    A destination outside the state tree is the user's own and keeps the plain
    behaviour.
    """
    dir_fd = _open_dest_dir(dest_path)
    if dir_fd is None:
        os.replace(src_path, dest_path)
        return
    try:
        os.replace(src_path, os.path.basename(dest_path), dst_dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def _staged(path: str, suffix: str, mode: int | None) -> Iterator[tuple[int, str]]:
    """Yield (descriptor, path) for a temporary beside *path*, published on success.

    The descriptor is the caller's to close; the temporary is this function's to
    remove if the block does not finish.
    """
    dest_dir = os.path.dirname(path) or "."
    dir_fd = _open_dest_dir(path)
    if dir_fd is None:
        fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=suffix, dir=dest_dir)
        src, dst = tmp, path
    else:
        src = dirfd.temp_name(os.path.basename(path), f".{os.getpid()}.{os.urandom(4).hex()}{suffix}")
        fd, _st = dirfd.open_new_at(dir_fd, src, 0o600)
        tmp, dst = os.path.join(dest_dir, src), os.path.basename(path)
    try:
        yield fd, tmp
        if mode is not None:
            # mode is chosen by the caller for the destination file; this helper
            # only applies it. The temp file was created 0o600 already.
            os.chmod(src, mode, dir_fd=dir_fd)  # lgtm[py/overly-permissive-file]
        os.replace(src, dst, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        if dir_fd is None:
            _fsync_directory(dest_dir)
        else:
            os.fsync(dir_fd)
    except BaseException:
        if dir_fd is None:
            with contextlib.suppress(OSError):
                os.remove(tmp)
        else:
            dirfd.unlink_quietly(dir_fd, src)
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


@contextlib.contextmanager
def atomic_replace(path: str, *, suffix: str = ".tmp", mode: int | None = None) -> Iterator[str]:
    """Yield a tmp path next to *path*; rename on success, remove on error.

    When *mode* is set it is applied to the temp file before rename (the temp
    file is created ``0o600``).

    .. note::
       Callers that write to the temp file themselves should ``flush()`` and
       ``os.fsync()`` the file descriptor **before** the ``with`` block exits,
       to ensure data reaches disk before the rename.  For the common case of
       writing text or bytes, prefer :func:`atomic_write` which handles this
       automatically.
    """
    with _staged(path, suffix, mode) as (fd, tmp):
        os.close(fd)
        yield tmp


@contextlib.contextmanager
def atomic_write(
    path: str,
    *,
    binary: bool = False,
    suffix: str = ".tmp",
    mode: int | None = None,
) -> Iterator[typing.IO[typing.Any]]:
    """Open a temp file for writing; flush, fsync, and rename on success.

    Yields an open file handle (text or binary depending on *binary*).
    On successful exit the data is flushed and fsynced before the temp file
    is renamed into *path*, guaranteeing that the destination never contains
    a partially-written file — even after a crash.
    """
    with _staged(path, suffix, mode) as (fd, _tmp):
        try:
            with open(fd, "wb" if binary else "w", closefd=True) as fh:
                yield fh
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            # fd is already closed by the open() context manager above
            # (closefd=True), but if the open() itself failed we still need to
            # close it.
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
