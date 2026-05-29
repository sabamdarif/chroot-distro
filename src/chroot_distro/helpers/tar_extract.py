import contextlib
import os
import shutil
import stat
import tarfile

from chroot_distro.progress import ByteCounter, clear_bar, draw_bytes_bar


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
    deferred_dirs: list = []   # (dest, mtime) — stamped after all writes

    with open(archive_path, "rb") as raw_fh:
        counter = ByteCounter(raw_fh)
        with tarfile.open(fileobj=counter, mode="r|*") as tf:
            for member in tf:
                _process_member(
                    member, tf, rootfs_dir,
                    strip=strip,
                    handle_whiteouts=handle_whiteouts,
                    deferred_links=deferred_links,
                    deferred_dirs=deferred_dirs,
                )
                draw_bytes_bar(counter.count, total_size)

    # All regular files written; now copy hard links. shutil.copy2
    # preserves mtime, which was already set above.
    for dest, src in deferred_links:
        if os.path.lexists(dest):
            with contextlib.suppress(OSError):
                os.remove(dest)
        if os.path.isfile(src):
            with contextlib.suppress(OSError):
                shutil.copy2(src, dest)

    # Stamp directory mtimes last (writing files into a dir bumps it).
    for path, mtime in reversed(deferred_dirs):
        with contextlib.suppress(OSError):
            os.utime(path, (mtime, mtime))

    clear_bar()


# ----- per-member dispatch -------------------------------------------------

def _process_member(member, tf, rootfs_dir, *, strip, handle_whiteouts,
                    deferred_links, deferred_dirs):
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

    parent = (
        os.path.join(rootfs_dir, *rel_parts[:-1])
        if len(rel_parts) > 1 else rootfs_dir
    )
    dest = os.path.join(rootfs_dir, rel_path)

    if handle_whiteouts and _apply_whiteout(rel_parts, parent):
        return

    os.makedirs(parent, exist_ok=True)

    if member.isdir():
        os.makedirs(dest, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(dest, stat.S_IMODE(member.mode) | stat.S_IRWXU)
        deferred_dirs.append((dest, member.mtime))

    elif member.issym():
        _write_symlink(dest, member)

    elif member.islnk():
        _defer_hardlink(member, rootfs_dir, strip, dest, deferred_links)

    elif member.isreg():
        _write_regular(dest, member, tf)


def _apply_whiteout(rel_parts, parent) -> bool:
    """Handle an OCI whiteout member. Returns True iff a whiteout was applied."""
    basename = rel_parts[-1]
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
    except OSError:
        pass


def _write_symlink(dest: str, member) -> None:
    if os.path.lexists(dest):
        _remove_fstree(dest)
    try:
        os.symlink(member.linkname, dest)
    except OSError:
        return
    with contextlib.suppress(OSError):
        os.utime(dest, (member.mtime, member.mtime), follow_symlinks=False)


def _defer_hardlink(member, rootfs_dir, strip, dest, deferred_links):
    """Queue a hardlink for copy after all regular files are written."""
    lparts = member.linkname.lstrip("/").rstrip("/").split("/")
    if len(lparts) <= strip:
        return
    rel_lparts = lparts[strip:]
    if any(p in ("..", "") for p in rel_lparts):
        return
    link_src = os.path.join(rootfs_dir, *rel_lparts)
    deferred_links.append((dest, link_src))


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
            os.chmod(dest, stat.S_IMODE(member.mode))
        with contextlib.suppress(OSError):
            os.utime(dest, (member.mtime, member.mtime))
    finally:
        fobj.close()
