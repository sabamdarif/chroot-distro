import contextlib
import os
import tempfile


@contextlib.contextmanager
def atomic_replace(path: str, *, suffix: str = ".tmp"):
    """Yield a tmp path next to *path*; rename on success, remove on error."""
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
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
