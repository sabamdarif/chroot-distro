"""Empty the download cache, or drop only the build cache.

Two deletion targets behind one command. The default takes the whole cache
directory; `--build-cache` takes the per-instruction build index and then the
layer blobs that nothing else names, so the downloaded base images -- the most
expensive thing here to re-acquire, and on a metered connection the wrong thing
to throw away -- stay where they are.
"""

import contextlib
import os
import shutil
import stat
import sys

from chroot_distro.constants import BASE_CACHE_DIR, LAYER_CACHE_DIR, PROGRAM_NAME
from chroot_distro.helpers.build_cache import discard_index, index_path
from chroot_distro.helpers.docker import layer_cache_path, referenced_blob_digests
from chroot_distro.locking import busy_locks
from chroot_distro.message import crit_error, log_error, log_info, quote_path, warn
from chroot_distro.progress import fmt_size


def _ensure_readable(path: str) -> None:
    """Attempt to add read/execute permissions to a directory entry."""
    try:
        st = os.stat(path)
        if os.path.isdir(path):
            os.chmod(path, st.st_mode | stat.S_IRWXU)
        else:
            os.chmod(path, st.st_mode | stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        warn(f"Failed to change permissions on cache path '{path}': {exc}")


def command_clear_cache(args) -> None:
    """Empty BASE_CACHE_DIR, or drop the build cache with --build-cache."""
    if getattr(args, "build_cache", False):
        _sweep_build_cache(args)
        return

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
                            log_info(f"Removing: '{os.path.join(dirpath, fname)}'")
                shutil.rmtree(entry.path)
            else:
                if verbose:
                    log_info(f"Removing: '{entry.path}'")
                os.remove(entry.path)
        except OSError as exc:
            log_error(f"Cannot remove '{entry.path}': {exc}")

    log_info(f"Reclaimed {fmt_size(total)} of disk space.")


# ---------------------------------------------------------------------------
# --build-cache
# ---------------------------------------------------------------------------


def _sweep_build_cache(args) -> None:
    """Drop the build index, then the layer blobs nothing else references.

    The keep set is computed before anything is deleted, so a reference source
    that cannot be read leaves the cache exactly as it was. The index then goes
    first and a failure to remove it stops the command before a blob it still
    pins is touched: unpinned-then-kept is untidy, pinned-then-deleted is the
    direction that matters.

    The index is never read, only unlinked, which is what makes the flag work on
    one too corrupt to parse -- among the reasons to reach for it. What survives
    is what a cached image lists, including every layer of an image a build
    produced, so what actually goes is the build's own bookkeeping, the
    intermediates no image kept (multi-stage stages, the output of steps rebuilt
    since), and the ordinary orphans a killed download or a local OCI install
    left behind.
    """
    verbose = getattr(args, "verbose", False)

    busy = busy_locks()
    if busy:
        crit_error(
            f"another {PROGRAM_NAME} command is running{busy[0][1]}. A build in progress has "
            f"recorded steps whose layers this would unpin, and it names them in the image it "
            f"stores last of all; try again once it has finished."
        )
        sys.exit(1)

    keep = _referenced_blob_names()
    index_removed, reclaimed = _drop_build_index(verbose)
    orphans, total = _collect_orphans(keep)

    if orphans:
        log_info(f"Removing {len(orphans)} unreferenced layer(s) ({fmt_size(total)})...")
    elif not index_removed:
        log_info("The build cache is already empty.")
        return

    failed = False
    for path, size in orphans:
        try:
            os.remove(path)
        except OSError as exc:
            log_error(f"Cannot remove '{quote_path(path)}': {quote_path(exc.strerror or str(exc))}")
            failed = True
            continue
        reclaimed += size
        if verbose:
            log_info(f"Removed: '{quote_path(path)}'")

    log_info(f"Reclaimed {fmt_size(reclaimed)} of disk space.")

    if failed:
        log_error("Finished with errors. Some files probably were not deleted.")
        sys.exit(1)


def _referenced_blob_names() -> set[str]:
    """Return the layer-cache file names a cached image still names.

    Digests are mapped forward into file names, never the reverse: a name in the
    cache is garbage exactly when no live reference produces it, which collects
    a download killed mid-flight for free. A digest too malformed to map to a
    path names no file here, since every writer validates before creating one.

    The manifest cache failing to answer ends the command rather than shrinking
    the set. An unreadable reference is not an absent one, and treating it as
    one deletes the layers of an image the user still has.
    """
    digests, unreadable = referenced_blob_digests()
    if unreadable:
        crit_error(
            f"cached image entry '{quote_path(unreadable[0])}' cannot be read, so the layers "
            f"it holds cannot be identified. Nothing was removed."
        )
        sys.exit(1)

    names = set()
    for digest in digests:
        try:
            names.add(os.path.basename(layer_cache_path(digest)))
        except RuntimeError:
            continue
    return names


def _drop_build_index(verbose: bool) -> tuple[bool, int]:
    """Delete the build-cache index, returning (removed, bytes reclaimed).

    Failure is fatal on purpose. The caller goes on to collect the layers this
    index was pinning, which is only correct once the entries naming them are
    gone.
    """
    try:
        removed, size = discard_index()
    except OSError as exc:
        crit_error(
            f"cannot remove the build cache index '{quote_path(index_path())}': "
            f"{quote_path(exc.strerror or str(exc))}. Nothing was removed."
        )
        sys.exit(1)

    if not removed:
        return False, 0
    if verbose:
        log_info(f"Removed: '{quote_path(index_path())}'")
    log_info(f"Removed the build cache index ({fmt_size(size)}).")
    return True, size


def _collect_orphans(keep: set[str]) -> tuple[list[tuple[str, int]], int]:
    """Return ([(path, size)], total_bytes) for every collectable blob.

    Only regular files are candidates: nothing writes a directory or a symlink
    into the layer cache, so leaving one alone costs nothing and keeps the sweep
    to a single file type.
    """
    try:
        names = sorted(os.listdir(LAYER_CACHE_DIR))
    except FileNotFoundError:
        return [], 0
    except OSError as exc:
        crit_error(f"cannot read the layer cache: {quote_path(exc.strerror or str(exc))}")
        sys.exit(1)

    orphans: list[tuple[str, int]] = []
    total = 0
    for name in names:
        if name in keep:
            continue
        path = os.path.join(LAYER_CACHE_DIR, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        orphans.append((path, st.st_size))
        total += st.st_size
    return orphans, total
