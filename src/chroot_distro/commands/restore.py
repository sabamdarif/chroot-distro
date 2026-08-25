# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro restore`: read a backup stream and rebuild one container from it.

The archive is input this program did not write, and the shape of this file follows
from that. Nothing destructive happens until a member that really will produce
content arrives: `_clear_existing_rootfs` runs at that commit point and not before,
the manifest is buffered and written only once a valid rootfs directory exists, and
an archive holding no rootfs at all therefore leaves the installed container as it
was.

Members are mapped, never extracted by name. `_dest_path` accepts `<name>/rootfs/...`
and the legacy `installed-rootfs/<name>/...` layout, refuses `..` and bare-root
members, and puts the container name through `is_valid_name`, so an archive names a
container but never a path. `_safe_dest` then clamps each write inside that
container's directory through `tar_extract._safe_resolve`, which is what defeats a
symlink an earlier member of the same archive planted; the last component is left
unresolved so the entry itself is what is acted on, and only a hard link's read
source resolves all the way.

One container per archive: the first valid member fixes the target and takes its
exclusive lock, and a member naming a second one ends the command. A hard link is
extracted as a copy, and device nodes, fifos and anything else unexpected are
skipped. A directory the archive wants unreadable is created wide and chmod'ed back
in reverse order at the end, so extraction can still descend into it.
"""

import contextlib
import os
import shutil
import stat
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import typing

import chroot_distro.helpers.mount_manager as mount_manager
from chroot_distro.commands.help import HELP_COMMANDS
from chroot_distro.constants import CONTAINERS_DIR, PROGRAM_NAME
from chroot_distro.helpers.tar_extract import _safe_resolve
from chroot_distro.locking import ContainerLock
from chroot_distro.message import (
    C,
    crit_error,
    log_error,
    log_info,
    msg,
    warn,
)
from chroot_distro.names import is_valid_name
from chroot_distro.paths import (
    container_dir,
    container_manifest,
    container_rootfs,
)
from chroot_distro.progress import (
    ByteCounter,
    clear_bar,
    draw_bytes_bar,
    progress_active,
)

_MAGIC_COMPRESS = (
    (b"\x1f\x8b", "gz"),  # gzip
    (b"BZh", "bz2"),  # bzip2
    (b"\xfd7zXZ\x00", "xz"),  # xz
    (b"\x5d\x00", "xz"),  # lzma legacy
    (b"\x28\xb5\x2f\xfd", "zst"),  # zstd
)

_LEGACY_PREFIX = "installed-rootfs"


def _detect_compression(header: bytes) -> str:
    """Return the tarfile mode suffix inferred from *header* magic bytes."""
    for magic, mode in _MAGIC_COMPRESS:
        if header.startswith(magic):
            return mode
    return ""


def _clear_existing_rootfs(container_name: str) -> None:
    """Remove the destination rootfs before extracting a new copy."""
    rootfs_dir = container_rootfs(container_name)
    if not os.path.isdir(rootfs_dir):
        return

    # Never clear a rootfs that still has active mounts.
    try:
        mount_manager.ensure_no_mounts(rootfs_dir)
    except Exception as e:
        crit_error(f"Failed mount safety check for container '{container_name}': {e}")
        sys.exit(1)

    pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"
    count = 0
    clear_bar()
    if progress_active() and not sys.stderr.isatty():
        sys.stderr.write(f"{pfx}Removing old rootfs...{C['RST']}\n")
        sys.stderr.flush()

    for dp, dns, fns in os.walk(rootfs_dir, topdown=False, followlinks=False):
        for fname in fns:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(dp, fname))
            count += 1
            if progress_active() and sys.stderr.isatty():
                sys.stderr.write(f"\r{pfx}Removing old rootfs... {count} files{C['RST']}")
                sys.stderr.flush()
        for dname in dns:
            with contextlib.suppress(OSError):
                os.rmdir(os.path.join(dp, dname))
    shutil.rmtree(rootfs_dir, ignore_errors=True)
    clear_bar()


def _remove_existing(dest: str, member: tarfile.TarInfo) -> None:
    """Remove any existing filesystem entry at *dest* before extraction."""
    try:
        if os.path.islink(dest) or os.path.isfile(dest):
            os.remove(dest)
        elif os.path.isdir(dest) and not member.isdir():
            shutil.rmtree(dest)
    except OSError as exc:
        warn(f"Failed to remove existing entry at {dest}: {exc}")


_SKIP = (None, None)


def _dest_path(member_name: str) -> tuple:
    """Map a TAR member name to (container_name, dest_path_in_containers)."""
    name = member_name.lstrip("/")
    if not name or name == ".":
        return _SKIP

    parts = name.split("/")

    if any(p in ("..", ".", "") for p in parts):
        return _SKIP

    if len(parts) == 1 and not name.endswith("/"):
        return _SKIP

    # Legacy format: installed-rootfs/<name>/...  ->  containers/<name>/rootfs/...
    if parts[0] == _LEGACY_PREFIX:
        if len(parts) < 2:
            return _SKIP
        container_name = parts[1]
        if not is_valid_name(container_name):
            return _SKIP
        rest = parts[2:]
        if not rest:
            return (container_name, container_rootfs(container_name))
        return (container_name, os.path.join(container_rootfs(container_name), *rest))

    # New format: <name>/...
    container_name = parts[0]
    if not is_valid_name(container_name):
        return _SKIP

    if len(parts) == 1:
        return (container_name, container_dir(container_name))

    sub = parts[1]
    rest = parts[2:]

    if sub == "manifest.json" and not rest:
        return (container_name, container_manifest(container_name))

    if sub == "rootfs":
        if not rest:
            return (container_name, container_rootfs(container_name))
        return (container_name, os.path.join(container_rootfs(container_name), *rest))

    return (container_name, os.path.join(container_rootfs(container_name), *parts[1:]))


def _is_rootfs_dest(container_name: str, dest: str) -> bool:
    """True if *dest* is the rootfs dir or lives inside it.

    Distinguishes real rootfs members (which commit the restore) from the
    top-level manifest.json.
    """
    rootfs = container_rootfs(container_name)
    return dest == rootfs or dest.startswith(rootfs + os.sep)


def _safe_dest(container_name: str, dest: str, *, follow_final: bool = False) -> str | None:
    """Clamp *dest* inside the container dir, defeating symlinks planted
    earlier in the same archive (e.g. `<name>/rootfs/evil -> /`).

    follow_final resolves the last component too (for a hardlink's read
    source); otherwise it's left alone so we act on the entry itself. Returns
    None on a symlink loop. Mirrors helpers/tar_extract.py.
    """
    root = container_dir(container_name)
    rel = os.path.relpath(dest, root)
    if rel == os.curdir:  # dest is the container dir itself
        return root
    parts = rel.split(os.sep)
    if os.pardir in parts:  # defensive: dest is always built under root
        return None
    if follow_final:
        return _safe_resolve(root, parts)
    safe_parent = _safe_resolve(root, parts[:-1])
    if safe_parent is None:
        return None
    return os.path.join(safe_parent, parts[-1])


def command_restore(args) -> None:
    """Restore a single container from a tar backup.

    The first valid member fixes the target container; members naming a
    different one are rejected. The destructive clear and the manifest write
    are both deferred until real rootfs content shows up, so a bad archive
    leaves the existing container untouched.
    """
    archive = getattr(args, "archive", None)
    verbose = getattr(args, "verbose", False)

    if archive:
        if not os.path.exists(archive):
            crit_error(f"file '{archive}' does not exist.")
            sys.exit(1)
        if os.path.isdir(archive):
            crit_error(f"path '{archive}' is a directory.")
            sys.exit(1)
        if not os.access(archive, os.R_OK):
            crit_error(f"file '{archive}' is not readable.")
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            msg()
            crit_error("archive file path is not specified and nothing is being piped via stdin.")
            HELP_COMMANDS["restore"]()
            sys.exit(1)

    os.makedirs(CONTAINERS_DIR, exist_ok=True)

    log_info("Restoring container from the backup...")

    done_size = 0
    total_size = 0
    counter: ByteCounter | None = None

    def _on_entry(member_size: int, member_name: str) -> None:
        nonlocal done_size
        done_size += member_size
        if verbose:
            log_info(f"Extracting: '{member_name}'")
        if counter is not None and total_size:
            draw_bytes_bar(counter.count, total_size)
        else:
            draw_bytes_bar(done_size, 0, noun="extracted")

    def _check_bare_root(member_name: str) -> bool:
        name = member_name.lstrip("/")
        if not name:
            return False
        parts = name.split("/")
        return len(parts) == 1 and not name.endswith("/")

    raw_fh = None
    restore_name: str | None = None
    lock = None
    committed = False
    pending_manifest = None  # (bytes, mode) written only on success
    # Dirs widened to owner-rwx for extraction; chmod'd back at the end.
    deferred_dir_modes: list[tuple[str, int]] = []

    def _write_manifest(data: bytes, mode: int) -> None:
        if restore_name is None:
            return
        mpath = container_manifest(restore_name)
        try:
            os.makedirs(os.path.dirname(mpath), exist_ok=True)
            with open(mpath, "wb") as out:
                out.write(data)
        except OSError:
            return
        with contextlib.suppress(OSError):
            os.chmod(mpath, mode)

    try:
        if archive:
            total_size = os.path.getsize(archive)
            raw_fh = open(archive, "rb")  # noqa: SIM115
            counter = ByteCounter(raw_fh)
            tf_fileobj: typing.Any = counter
            tf_mode = "r|*"
        else:
            import io

            buf = sys.stdin.buffer
            header = buf.peek(6)[:6] if isinstance(buf, io.BufferedReader) else b""
            comp = _detect_compression(header)
            tf_fileobj = sys.stdin.buffer
            tf_mode = f"r|{comp}"

        with tarfile.open(fileobj=tf_fileobj, mode=tf_mode) as tf:  # type: ignore[call-overload]
            for member in tf:
                if member.isblk() or member.ischr() or member.isfifo():
                    continue

                if _check_bare_root(member.name):
                    clear_bar()
                    log_error("Cannot restore: provided file has invalid structure.")
                    sys.exit(1)

                container_name, dest = _dest_path(member.name)
                if container_name is None:
                    continue

                # First valid member fixes the target and takes its lock.
                if restore_name is None:
                    restore_name = container_name
                    lock = ContainerLock(container_name, exclusive=True, command="restore")
                    if not lock.acquire():
                        hint = lock.holder_hint()
                        clear_bar()
                        log_error(f"Cannot restore: container '{container_name}' is busy{hint}.")
                        sys.exit(1)
                    log_info(f"Destination: {restore_name}")
                elif container_name != restore_name:
                    clear_bar()
                    log_error(
                        f"Cannot restore: archive contains more than one container "
                        f"('{restore_name}' and '{container_name}'). "
                        f"Restore handles a single container at a time."
                    )
                    sys.exit(1)

                assert restore_name is not None

                # Buffer the manifest until the restore succeeds; other
                # non-rootfs members are ignored.
                if not _is_rootfs_dest(restore_name, dest):
                    if member.isreg() and dest == container_manifest(restore_name):
                        fobj = tf.extractfile(member)
                        data = b""
                        if fobj is not None:
                            try:
                                data = fobj.read()
                            finally:
                                fobj.close()
                        pending_manifest = (data, stat.S_IMODE(member.mode))
                        _on_entry(member.size, member.name)
                    continue

                # Clamp the write inside the container dir.
                dest = _safe_dest(restore_name, dest)
                if dest is None:
                    continue

                # Skip members that won't materialise *before* clearing
                # anything, so a bad archive never destroys the old rootfs.
                link_src = None
                if member.islnk():
                    link_container, raw_src = _dest_path(member.linkname)
                    if raw_src is None or link_container != restore_name:
                        continue
                    link_src = _safe_dest(link_container, raw_src, follow_final=True)
                    if link_src is None:
                        continue
                elif not (member.isdir() or member.issym() or member.isreg()):
                    continue

                # Destructive commit point: this member produces real content.
                if not committed:
                    _clear_existing_rootfs(restore_name)
                    committed = True

                _remove_existing(dest, member)

                if member.isdir():
                    os.makedirs(dest, exist_ok=True)
                    mode = stat.S_IMODE(member.mode)
                    if (mode & stat.S_IRWXU) != stat.S_IRWXU:
                        with contextlib.suppress(OSError):
                            os.chmod(dest, mode | stat.S_IRWXU)
                        deferred_dir_modes.append((dest, mode))
                    else:
                        with contextlib.suppress(OSError):
                            os.chmod(dest, mode)
                    with contextlib.suppress(OSError):
                        os.lchown(dest, member.uid, member.gid)

                elif member.issym():
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    os.symlink(member.linkname, dest)
                    with contextlib.suppress(OSError):
                        os.lchown(dest, member.uid, member.gid)

                elif member.islnk():
                    assert link_src is not None
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    try:
                        shutil.copy2(link_src, dest)
                        with contextlib.suppress(OSError):
                            os.lchown(dest, member.uid, member.gid)
                        if member.mode:
                            with contextlib.suppress(OSError):
                                os.chmod(dest, stat.S_IMODE(member.mode))
                    except OSError as exc:
                        warn(f"Failed to extract hard link fallback {member.name} to {dest}: {exc}")

                elif member.isreg():
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    try:
                        with open(dest, "wb") as out:
                            while True:
                                chunk = fobj.read(1 << 17)
                                if not chunk:
                                    break
                                out.write(chunk)
                        with contextlib.suppress(OSError):
                            os.lchown(dest, member.uid, member.gid)
                        with contextlib.suppress(OSError):
                            os.chmod(dest, stat.S_IMODE(member.mode))
                    except OSError as exc:
                        warn(f"Failed to extract file {member.name} to {dest}: {exc}")
                    finally:
                        fobj.close()

                _on_entry(member.size, member.name)

        # Nothing was written: the target was never touched.
        if not committed:
            clear_bar()
            log_error(
                f"Cannot restore: archive does not contain a container rootfs. "
                f"Only archives created by '{PROGRAM_NAME} backup' are supported."
            )
            sys.exit(1)

        assert restore_name is not None
        rootfs_dir = container_rootfs(restore_name)
        if os.path.islink(rootfs_dir) or not os.path.isdir(rootfs_dir):
            # Rootfs came out as a file/symlink: drop the partial result.
            clear_bar()
            shutil.rmtree(container_dir(restore_name), ignore_errors=True)
            log_error(
                f"Cannot restore: archive did not produce a valid container rootfs. "
                f"Only archives created by '{PROGRAM_NAME} backup' are supported."
            )
            sys.exit(1)

        for path, mode in reversed(deferred_dir_modes):
            with contextlib.suppress(OSError):
                os.chmod(path, mode)

        # Write the buffered manifest now that the rootfs is confirmed.
        if pending_manifest is not None:
            _write_manifest(*pending_manifest)

        clear_bar()
        log_info("Finished restoring the container.")

    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        sys.exit(1)
    except (EOFError, OSError, tarfile.TarError) as exc:
        clear_bar()
        log_error(f"Failed to restore container: {exc}")
        sys.exit(1)
    finally:
        if raw_fh is not None:
            raw_fh.close()
        if lock is not None:
            lock.release()
