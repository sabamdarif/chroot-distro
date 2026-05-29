import contextlib
import os
import shutil
import stat

from chroot_distro.constants import BASE_CACHE_DIR
from chroot_distro.message import log_error, log_info
from chroot_distro.progress import fmt_size


def _ensure_readable(path: str) -> None:
    """Attempt to add read/execute permissions to a directory entry."""
    try:
        st = os.stat(path)
        if os.path.isdir(path):
            os.chmod(path, st.st_mode | stat.S_IRWXU)
        else:
            os.chmod(path, st.st_mode | stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def command_clear_cache(args) -> None:
    """Empty BASE_CACHE_DIR (Docker layers + manifests + build cache)."""
    verbose = getattr(args, "verbose", False)

    if not os.path.isdir(BASE_CACHE_DIR):
        log_info("Cache is empty.")
        return

    total = 0
    for dirpath, _dirs, filenames in os.walk(BASE_CACHE_DIR):
        _ensure_readable(dirpath)
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            _ensure_readable(fpath)
            with contextlib.suppress(OSError):
                total += os.path.getsize(fpath)

    if total == 0 and not any(True for _ in os.scandir(BASE_CACHE_DIR)):
        log_info("Cache is empty.")
        return

    log_info("Clearing cache...")

    for entry in os.scandir(BASE_CACHE_DIR):
        try:
            if entry.is_dir(follow_symlinks=False):
                if verbose:
                    for dirpath, _dirs, filenames in os.walk(entry.path):
                        for fname in filenames:
                            log_info(
                                f"Removing: '{os.path.join(dirpath, fname)}'"
                            )
                shutil.rmtree(entry.path)
            else:
                if verbose:
                    log_info(f"Removing: '{entry.path}'")
                os.remove(entry.path)
        except OSError as exc:
            log_error(f"Cannot remove '{entry.path}': {exc}")

    log_info(f"Reclaimed {fmt_size(total)} of disk space.")
