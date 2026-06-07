import contextlib
import os
import sys
import tempfile


def _fsync_directory(dir_path: str) -> None:
    """Fsync a directory to ensure rename/link metadata reaches disk."""
    if sys.platform != "win32":
        fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextlib.contextmanager
def atomic_replace(path: str, *, suffix: str = ".tmp", mode: int | None = None):
    """Yield a tmp path next to *path*; rename on success, remove on error.

    When *mode* is set it is applied to the temp file before rename (``mkstemp``
    creates mode ``0o600`` by default).

    .. note::
       Callers that write to the temp file themselves should ``flush()`` and
       ``os.fsync()`` the file descriptor **before** the ``with`` block exits,
       to ensure data reaches disk before the rename.  For the common case of
       writing text or bytes, prefer :func:`atomic_write` which handles this
       automatically.
    """
    dest_dir = os.path.dirname(path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=suffix,
        dir=dest_dir,
    )
    os.close(fd)
    try:
        yield tmp
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_directory(dest_dir)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


@contextlib.contextmanager
def atomic_write(
    path: str,
    *,
    binary: bool = False,
    suffix: str = ".tmp",
    mode: int | None = None,
):
    """Open a temp file for writing; flush, fsync, and rename on success.

    Yields an open file handle (text or binary depending on *binary*).
    On successful exit the data is flushed and fsynced before the temp file
    is renamed into *path*, guaranteeing that the destination never contains
    a partially-written file — even after a crash.
    """
    dest_dir = os.path.dirname(path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=suffix,
        dir=dest_dir,
    )
    try:
        with open(fd, "wb" if binary else "w", closefd=True) as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_directory(dest_dir)
    except BaseException:
        # fd is already closed by the open() context manager above (closefd=True),
        # but if the open() itself failed we still need to close it.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
