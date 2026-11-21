# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Restore one container from the layout written by the backup command.

Members use <name>/rootfs and an optional <name>/manifest.json. The first
member fixes the container name and takes its lock. The first rootfs member
starts a marked install. Extraction and retries use pinned directories, and
hardlinks become copies of files in the guest rootfs.
The incomplete marker survives errors and interrupts and is removed only after
the tar terminator and compression stream have been checked and the optional
manifest has been written.
"""

import bz2
import contextlib
import errno
import gzip
import io
import lzma
import os
import shutil
import stat
import sys
import tempfile
import typing
import zlib

if sys.version_info >= (3, 14):
    import tarfile as tar

    from compression import zstd
else:
    from backports import zstd
    from backports.zstd import tarfile as tar

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.commands.help import HELP_COMMANDS
from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.helpers.install_state import (
    clear_incomplete_rootfs,
    create_install_rootfs,
    finish_install,
    write_incomplete_marker,
)
from chroot_distro.helpers.tar_extract import safe_resolve_parts_at
from chroot_distro.locking import ContainerLock
from chroot_distro.message import (
    crit_error,
    escape_controls,
    log_error,
    log_info,
    msg,
    quote_path,
)
from chroot_distro.names import is_valid_name
from chroot_distro.paths import (
    container_incomplete_marker,
    container_manifest,
    container_rootfs,
    open_container_dir,
)
from chroot_distro.progress import (
    ByteCounter,
    clear_bar,
    draw_bytes_bar,
)
from chroot_distro.syscalls.mount import fd_path

_MAGIC_COMPRESS = (
    (b"\x1f\x8b", "gz"),  # gzip
    (b"\xfd7zXZ\x00", "xz"),  # xz
    (b"\x5d\x00", "xz"),  # lzma legacy
    (b"\x28\xb5\x2f\xfd", "zst"),  # zstd
)


def _detect_compression(header: bytes) -> str:
    """Return the tarfile mode suffix inferred from *header* magic bytes."""
    if header.startswith(b"BZh") and b"1" <= header[3:4] <= b"9" and header[4:10] in (b"1AY&SY", b"\x17rE8P\x90"):
        return "bz2"
    for magic, mode in _MAGIC_COMPRESS:
        if header.startswith(magic):
            return mode
    return ""


class _BackupInput(io.RawIOBase):
    """Replay the compression header before continuing from a file or pipe."""

    def __init__(self, source: ByteCounter) -> None:
        self._source = source
        self._prefix = source.read(10)
        while len(self._prefix) < 10:
            chunk = source.read(10 - len(self._prefix))
            if not chunk:
                break
            self._prefix += chunk
        self.compression = _detect_compression(self._prefix)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer, /) -> int:
        if not self._prefix:
            return typing.cast(int, self._source.readinto(buffer))
        view = memoryview(buffer)
        size = min(len(view), len(self._prefix))
        view[:size] = self._prefix[:size]
        self._prefix = self._prefix[size:]
        return size


class _BackupTarInfo(tar.TarInfo):
    """Distinguish a complete tar archive from a bad or missing header."""

    @classmethod
    def fromtarfile(cls, tarfile: tar.TarFile) -> "_BackupTarInfo":
        try:
            return super().fromtarfile(tarfile)
        except tar.EOFHeaderError:  # type: ignore[attr-defined]
            stream = tarfile.fileobj
            if stream.read(tar.BLOCKSIZE) != bytes(tar.BLOCKSIZE):
                raise tar.ReadError("tar archive must end with two zero blocks") from None
            while padding := stream.read(1 << 17):
                if padding.count(0) != len(padding):
                    raise tar.ReadError("unexpected data after the tar terminator") from None
            raise
        except tar.HeaderError as exc:
            raise tar.ReadError(f"invalid tar header or terminator: {exc}") from exc


def _open_backup(source: ByteCounter, sources: contextlib.ExitStack) -> tar.TarFile:
    archive = _BackupInput(source)
    stream = sources.enter_context(io.BufferedReader(archive))
    decoded: typing.Any = stream
    if archive.compression == "gz":
        decoded = sources.enter_context(gzip.GzipFile(fileobj=stream, mode="rb"))
    elif archive.compression == "bz2":
        decoded = sources.enter_context(bz2.BZ2File(stream))
    elif archive.compression == "xz":
        decoded = sources.enter_context(lzma.LZMAFile(stream))  # noqa: SIM115
    elif archive.compression == "zst":
        decoded = sources.enter_context(zstd.ZstdFile(stream))
    return sources.enter_context(tar.open(fileobj=decoded, mode="r|", tarinfo=_BackupTarInfo))


def _dest_path(path: str) -> tuple[str, tuple[str, ...] | None] | None:
    """Map to a container and rootfs-relative parts, using None for its manifest."""
    parts = tuple(path.lstrip("/").split("/"))
    if len(parts) < 2 or not is_valid_name(parts[0]) or any(part in ("..", ".", "") for part in parts):
        return None

    name, sub = parts[:2]
    if sub == "manifest.json" and len(parts) == 2:
        return name, None
    if sub == "rootfs":
        return name, parts[2:]
    return None


def _start_restore(name: str, pins: contextlib.ExitStack) -> tuple[int, int, str]:
    container_fd = open_container_dir(name, create=True)
    pins.callback(os.close, container_fd)
    marker = os.path.basename(container_incomplete_marker(name))
    rootfs = os.path.basename(container_rootfs(name))
    try:
        dirfd.lstat_at(container_fd, marker)
    except FileNotFoundError:
        incomplete = False
    else:
        incomplete = True
    try:
        rootfs_fd = dirfd.opendir_at(container_fd, rootfs)
    except FileNotFoundError:
        rootfs_fd = create_install_rootfs(container_fd, rootfs, marker, incomplete=incomplete)
        pins.callback(os.close, rootfs_fd)
    else:
        pins.callback(os.close, rootfs_fd)
        if not incomplete:
            raise ChrootDistroError(
                f"container '{name}' is already installed. "
                f"Remove it first ('{PROGRAM_NAME} remove {name}'), or bring "
                f"the backup in under a new name with '{PROGRAM_NAME} install <archive> --name NEWNAME'."
            )
        write_incomplete_marker(marker, dir_fd=container_fd)
        clear_incomplete_rootfs(name, container_fd, rootfs_fd)
        os.fchown(rootfs_fd, os.geteuid(), os.getegid())
        os.fchmod(rootfs_fd, 0o755)

    with contextlib.suppress(FileNotFoundError):
        os.unlink(os.path.basename(container_manifest(name)), dir_fd=container_fd)
    return container_fd, rootfs_fd, marker


def _open_hardlink(rootfs_fd: int, link_parts: tuple[str, ...]) -> tuple[int, os.stat_result]:
    resolved = safe_resolve_parts_at(rootfs_fd, link_parts)
    if not resolved:
        raise OSError(errno.EINVAL, "hardlink target does not resolve to a guest file")
    parent_fd = dirfd.descend_at(rootfs_fd, resolved[:-1])
    try:
        original = dirfd.lstat_at(parent_fd, resolved[-1])
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
            raise OSError(errno.EINVAL, "hardlink target must be a singly linked regular file")
        source_fd, opened = dirfd.open_regular_at(parent_fd, resolved[-1], os.O_RDONLY)
        if opened.st_nlink != 1 or not os.path.samestat(original, opened):
            os.close(source_fd)
            raise OSError(errno.ESTALE, "hardlink target was replaced")
        return source_fd, opened
    finally:
        os.close(parent_fd)


_DirModes = dict[tuple[str, ...], tuple[os.stat_result, int]]


# The procfs path addresses the symlink inode pinned with O_PATH and O_NOFOLLOW.
def _restore_symlink(parent_fd: int, leaf: str, member: tar.TarInfo) -> None:
    os.symlink(member.linkname, leaf, dir_fd=parent_fd)
    fd = dirfd.open_file_at(parent_fd, leaf, os.O_PATH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
            raise OSError(errno.ESTALE, "symlink was replaced or linked during restore", leaf)
        os.chown(fd_path(fd), member.uid, member.gid)
    finally:
        os.close(fd)


def _restore_member(
    tf: tar.TarFile,
    member: tar.TarInfo,
    name: str,
    rootfs_fd: int,
    parts: tuple[str, ...],
    modes: _DirModes,
) -> None:
    mode = stat.S_IMODE(member.mode)
    if not parts:
        os.fchown(rootfs_fd, member.uid, member.gid)
        modes[()] = (os.fstat(rootfs_fd), mode)
        return

    parents = safe_resolve_parts_at(rootfs_fd, parts[:-1])
    if parents is None:
        raise OSError(errno.ELOOP, "archive member parent could not be resolved")
    leaf = parts[-1]
    target = (*parents, leaf)
    parent_fd = dirfd.descend_at(rootfs_fd, parents, create=True)
    with contextlib.ExitStack() as pins:
        pins.callback(os.close, parent_fd)
        if member.isdir():
            try:
                existing = dirfd.lstat_at(parent_fd, leaf)
            except FileNotFoundError:
                existing = None
            if existing is None or not stat.S_ISDIR(existing.st_mode):
                if existing is not None:
                    dirfd.rmtree_at(parent_fd, leaf, force=True)
                os.mkdir(leaf, dir_fd=parent_fd)
            fd = dirfd.opendir_at(parent_fd, leaf)
            try:
                os.fchown(fd, member.uid, member.gid)
                os.fchmod(fd, mode | stat.S_IRWXU)
                if mode & stat.S_IRWXU == stat.S_IRWXU:
                    modes.pop(target, None)
                else:
                    modes[target] = (os.fstat(fd), mode)
            finally:
                os.close(fd)
            return

        modes.pop(target, None)
        link = None
        if member.islnk():
            source = _dest_path(member.linkname)
            if source is None or source[0] != name or source[1] is None:
                raise OSError(errno.EINVAL, "hardlink target is outside the guest rootfs")
            link = _open_hardlink(rootfs_fd, source[1])
            pins.callback(os.close, link[0])
        dirfd.rmtree_at(parent_fd, leaf, force=True)
        if member.issym():
            _restore_symlink(parent_fd, leaf, member)
            return

        fd, _ = dirfd.open_new_at(parent_fd, leaf, 0o600)
        pins.callback(os.close, fd)
        if link is not None:
            source_fd, source_st = link
            dirfd.copy_data(source_fd, fd, source_st)
            os.utime(fd, ns=(source_st.st_atime_ns, source_st.st_mtime_ns))
            mode = mode or stat.S_IMODE(source_st.st_mode)
        else:
            content = tf.extractfile(member)
            if content is None:
                raise tar.ReadError("regular archive member has no data stream")
            with content, open(fd, "wb", closefd=False) as out:
                shutil.copyfileobj(content, out, 1 << 17)
        os.fchown(fd, member.uid, member.gid)
        os.fchmod(fd, mode)


def _apply_dir_modes(rootfs_fd: int, modes: _DirModes) -> None:
    for parts in sorted(modes, key=len, reverse=True):
        previous, mode = modes[parts]
        try:
            fd = dirfd.descend_at(rootfs_fd, parts)
        except (FileNotFoundError, NotADirectoryError):
            continue
        try:
            if os.path.samestat(previous, os.fstat(fd)):
                os.fchmod(fd, mode)
        finally:
            os.close(fd)


def _restore_stream(
    tf: tar.TarFile,
    on_entry: typing.Callable[[int, str], None],
    pins: contextlib.ExitStack,
) -> tuple[str, int, int, str]:
    name = None
    opened = None
    manifest = None
    manifest_mode = 0
    modes: _DirModes = {}
    for member in tf:
        if not (member.isdir() or member.isreg() or member.issym() or member.islnk()):
            continue

        destination = _dest_path(member.name)
        if destination is None:
            raise ChrootDistroError("archive members must use <name>/rootfs/... or <name>/manifest.json.")
        member_name, parts = destination
        if parts == () and not member.isdir():
            raise ChrootDistroError("the archive rootfs entry must be a directory.")
        if parts is None and member.isdir():
            raise ChrootDistroError("the archive manifest entry cannot be a directory.")
        if name is None:
            name = member_name
            lock = ContainerLock(name, exclusive=True, command="restore")
            pins.callback(lock.release)
            if not lock.acquire():
                raise ChrootDistroError(str(lock.conflict_error()))
            log_info(f"Destination: {name}")
        elif member_name != name:
            raise ChrootDistroError(
                f"archive contains more than one container ('{name}' and '{member_name}'). "
                "Restore handles a single container at a time."
            )

        if parts is not None:
            if opened is None:
                opened = _start_restore(name, pins)
            _, rootfs_fd, _ = opened
            _restore_member(tf, member, name, rootfs_fd, parts, modes)
        elif member.isreg():
            if manifest is None:
                manifest = pins.enter_context(tempfile.SpooledTemporaryFile(max_size=1 << 20))  # noqa: SIM115
            manifest.seek(0)
            manifest.truncate()
            content = tf.extractfile(member)
            if content is None:
                raise tar.ReadError("manifest has no data stream")
            with content:
                shutil.copyfileobj(content, manifest, 1 << 17)
            manifest_mode = stat.S_IMODE(member.mode)
        else:
            continue
        on_entry(member.size, member.name)

    if opened is None:
        raise ChrootDistroError(
            f"archive does not contain a container rootfs. "
            f"Only archives created by '{PROGRAM_NAME} backup' are supported."
        )
    assert name is not None
    container_fd, rootfs_fd, marker = opened
    _apply_dir_modes(rootfs_fd, modes)
    if manifest is not None:
        manifest.seek(0)
        manifest_leaf = os.path.basename(container_manifest(name))
        with atomic_write(manifest_leaf, binary_mode=True, mode=manifest_mode, dir_fd=container_fd) as out:
            shutil.copyfileobj(manifest, out, 1 << 17)
    return name, container_fd, rootfs_fd, marker


def command_restore(args) -> None:
    """Restore a single container from a tar backup."""
    archive = getattr(args, "archive", None)
    verbose = getattr(args, "verbose", False)

    if archive:
        archive = os.path.expanduser(archive)
        if not os.path.exists(archive) and archive.startswith("./"):
            cleaned = "/" + archive.lstrip("./")
            if os.path.exists(cleaned):
                archive = cleaned
        if not os.path.exists(archive):
            crit_error(f"file '{quote_path(archive)}' does not exist.")
            sys.exit(1)
        if os.path.isdir(archive):
            crit_error(f"path '{quote_path(archive)}' is a directory.")
            sys.exit(1)
        if not os.access(archive, os.R_OK):
            crit_error(f"file '{quote_path(archive)}' is not readable.")
            sys.exit(1)
    elif sys.stdin.isatty():
        msg()
        crit_error("archive file path is not specified and nothing is being piped via stdin.")
        HELP_COMMANDS["restore"]()
        sys.exit(1)

    log_info("Restoring container from the backup...")

    done_size = 0
    total_size = 0

    def _on_entry(member_size: int, member_name: str) -> None:
        nonlocal done_size
        done_size += member_size
        if verbose:
            log_info(f"Extracting: '{quote_path(member_name)}'")
        if total_size:
            draw_bytes_bar(counter.count, total_size)
        else:
            draw_bytes_bar(done_size, 0, noun="extracted")

    try:
        with contextlib.ExitStack() as pins:
            with contextlib.ExitStack() as sources:
                raw: typing.BinaryIO
                if archive:
                    raw = sources.enter_context(open(archive, "rb"))
                    total_size = os.fstat(raw.fileno()).st_size
                else:
                    raw = sys.stdin.buffer
                counter = ByteCounter(raw)
                tf = _open_backup(counter, sources)
                result = _restore_stream(tf, _on_entry, pins)
            finish_install(*result)

    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        sys.exit(1)
    except (
        ChrootDistroError,
        EOFError,
        OSError,
        OverflowError,
        ValueError,
        lzma.LZMAError,
        tar.TarError,
        zlib.error,
        zstd.ZstdError,
    ) as exc:
        clear_bar()
        log_error(f"Failed to restore container: {escape_controls(str(exc))}")
        sys.exit(1)

    clear_bar()
    log_info("Finished restoring the container.")
