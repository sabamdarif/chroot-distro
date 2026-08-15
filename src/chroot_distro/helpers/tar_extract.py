import contextlib
import logging
import os
import shutil
import stat
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro.progress import ByteCounter, clear_bar, draw_bytes_bar

log = logging.getLogger(__name__)


def extract_tar_to_rootfs(
    archive_path: str,
    rootfs_dir: str,
    *,
    strip: int = 0,
    handle_whiteouts: bool = False,
) -> None:
    """Stream-extract *archive_path* into *rootfs_dir*.

    See module docstring for the shared invariants. The function
    consumes a compressed-or-not tar stream via tarfile's `'r|*'`
    auto-detect, so it works for raw tar, .tar.gz, .tar.bz2, .tar.xz,
    and a Docker/OCI layer blob alike.
    """
    total_size = os.path.getsize(archive_path)
    deferred_links: list = []  # (dest, src) — copied after all regular files
    deferred_dirs: list = []  # (dest, mtime) — stamped after all writes

    with open(archive_path, "rb") as raw_fh:
        counter = ByteCounter(raw_fh)
        import typing

        with tarfile.open(fileobj=typing.cast(typing.Any, counter), mode="r|*") as tf:
            for member in tf:
                _process_member(
                    member,
                    tf,
                    rootfs_dir,
                    strip=strip,
                    handle_whiteouts=handle_whiteouts,
                    deferred_links=deferred_links,
                    deferred_dirs=deferred_dirs,
                )
                draw_bytes_bar(counter.count, total_size)

    # All regular files written; now copy hard links. shutil.copy2
    # preserves mtime, which was already set above. Both endpoints are
    # re-resolved here (not at defer time) so a symlink planted by a
    # later member can't redirect either the read source or the write
    # dest outside the rootfs.
    for dest_parts, src_parts, uid, gid in deferred_links:
        parent = _safe_resolve(rootfs_dir, dest_parts[:-1])
        if parent is None:
            continue
        dest = os.path.join(parent, dest_parts[-1])
        src = _safe_resolve(rootfs_dir, src_parts)
        if src is None:
            continue
        if os.path.lexists(dest):
            with contextlib.suppress(OSError):
                os.remove(dest)
        if os.path.isfile(src):
            with contextlib.suppress(OSError):
                shutil.copy2(src, dest)
                os.lchown(dest, uid, gid)

    # Stamp directory mtimes last (writing files into a dir bumps it).
    for path, mtime in reversed(deferred_dirs):
        with contextlib.suppress(OSError):
            os.utime(path, (mtime, mtime))

    clear_bar()


# ----- per-member dispatch -------------------------------------------------


def _process_member(member, tf, rootfs_dir, *, strip, handle_whiteouts, deferred_links, deferred_dirs):
    if member.isblk() or member.ischr() or member.isfifo():
        return

    parts = member.name.lstrip("/").rstrip("/").split("/")
    if len(parts) <= strip:
        return
    rel_parts = parts[strip:]
    if any(p in ("..", "") for p in rel_parts):
        return

    rel_path = "/".join(rel_parts)
    if not rel_path or rel_path == ".":
        return

    # Resolve the destination's parent through any pre-existing symlink
    # components, clamping every hop inside rootfs_dir (see module
    # docstring). The final component is deliberately *not* followed so
    # we operate on the entry itself, never on whatever a same-named
    # symlink points at.
    parent = _safe_resolve(rootfs_dir, rel_parts[:-1])
    if parent is None:
        return
    dest = os.path.join(parent, rel_parts[-1])

    # For whiteouts, use the non-symlink-resolved parent to avoid deleting
    # through symlinks. Compute parent_no_follow by manually joining path
    # components without resolving symlinks.
    if handle_whiteouts:
        parent_no_follow = os.path.join(rootfs_dir, *rel_parts[:-1]) if len(rel_parts) > 1 else rootfs_dir
        if _apply_whiteout(rel_parts, parent_no_follow):
            return

    os.makedirs(parent, exist_ok=True)

    if member.isdir():
        # A symlink already occupying this name would make os.makedirs
        # (and the chmod/utime below) act on its target, so drop it
        # first — overlay semantics replace a symlink with a real dir.
        if os.path.islink(dest):
            _remove_fstree(dest)
        os.makedirs(dest, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(dest, stat.S_IMODE(member.mode) | stat.S_IRWXU)
        with contextlib.suppress(OSError):
            os.lchown(dest, member.uid, member.gid)
        deferred_dirs.append((dest, member.mtime))

    elif member.issym():
        _write_symlink(dest, member)

    elif member.islnk():
        _defer_hardlink(member, strip, rel_parts, deferred_links)

    elif member.isreg():
        _write_regular(dest, member, tf)


def _apply_whiteout(rel_parts, parent) -> bool:
    """Handle an OCI whiteout member. Returns True iff a whiteout was applied."""
    basename = rel_parts[-1]

    # If parent is a symlink, don't follow it for whiteout operations.
    # Whiteouts apply to the overlay layer, not to symlink targets.
    # Use lexists to check existence without following symlinks.
    if not os.path.lexists(parent):
        return True
    if os.path.islink(parent):
        return True

    if basename == ".wh..wh..opq":
        # Opaque whiteout: clear everything inside the parent dir.
        if os.path.isdir(parent):
            for entry in os.listdir(parent):
                _remove_fstree(os.path.join(parent, entry))
        return True
    if basename.startswith(".wh."):
        # Regular whiteout: delete the named sibling.
        _remove_fstree(os.path.join(parent, basename[4:]))
        return True
    return False


def _remove_fstree(path: str) -> None:
    """Remove a file, symlink, or directory tree; ignore all errors."""
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)
    except OSError as exc:
        log.debug("Failed to remove fstree %s: %s", path, exc)


def _write_symlink(dest: str, member) -> None:
    if os.path.lexists(dest):
        _remove_fstree(dest)
    try:
        os.symlink(member.linkname, dest)
    except OSError:
        return
    with contextlib.suppress(OSError):
        os.lchown(dest, member.uid, member.gid)
    with contextlib.suppress(OSError):
        os.utime(dest, (member.mtime, member.mtime), follow_symlinks=False)


def _defer_hardlink(member, strip, rel_parts, deferred_links):
    """Queue a hardlink for copy after all regular files are written.

    The linkname is filtered identically to member.name: leading slashes
    stripped, path elements containing ".." or empty parts rejected. Without
    this filtering, a linkname could point at a host path (e.g.
    "../../etc/shadow") and shutil.copy2 would resolve it through the rootfs
    prefix, copying host content into the member-defined dest inside the
    rootfs.

    Only the (validated) relative components of both endpoints are stored;
    the on-disk paths are resolved with _safe_resolve at copy time so a
    symlink planted by a later member can't redirect the read source or the
    write dest out of the rootfs.
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

    Walks *parts* component by component starting at *root*. Existing
    symlink components are followed, but their targets are interpreted
    relative to *root*: an absolute target re-roots at *root* and ".."
    can never ascend above it. This both blocks symlink-traversal
    escapes and matches proot's runtime view, where the guest '/' is
    the rootfs, so legitimate absolute symlinks resolve to the right
    in-rootfs location. Components that don't exist yet are taken
    verbatim (a not-yet-written subtree can't be a symlink).

    Returns an absolute path guaranteed to live within *root*, or None
    if a symlink loop / excessive chain is hit (caller skips the entry).
    Pass parent components only when the final element must not be
    followed (file/dir/symlink writes); pass the full path to resolve a
    hardlink's source file.
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
        current = os.path.join(root, *resolved, comp)
        try:
            st = os.lstat(current)
        except OSError:
            # Doesn't exist yet (or unreadable) — safe to take as-is.
            resolved.append(comp)
            continue
        if stat.S_ISLNK(st.st_mode):
            link_budget -= 1
            if link_budget < 0:
                return None
            try:
                target = os.readlink(current)
            except OSError:
                return None
            tparts = target.split("/")
            if target.startswith("/"):
                resolved = []  # absolute target: re-root at *root*
            pending[:0] = tparts
        else:
            resolved.append(comp)
    return os.path.join(root, *resolved)


def _write_regular(dest: str, member, tf) -> None:
    fobj = tf.extractfile(member)
    if fobj is None:
        return
    if os.path.lexists(dest):
        with contextlib.suppress(OSError):
            os.remove(dest)
    try:
        with open(dest, "wb") as out:
            shutil.copyfileobj(fobj, out, 1 << 17)  # 128 KiB chunks
        with contextlib.suppress(OSError):
            os.lchown(dest, member.uid, member.gid)
        with contextlib.suppress(OSError):
            os.chmod(dest, stat.S_IMODE(member.mode))
        with contextlib.suppress(OSError):
            os.utime(dest, (member.mtime, member.mtime))
    finally:
        fobj.close()
