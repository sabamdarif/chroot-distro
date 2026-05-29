import contextlib
import os
import stat
import sys
import tarfile

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_error, log_info
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_manifest, container_rootfs
from chroot_distro.progress import (
    REDRAW_THRESHOLD_BYTES,
    clear_bar,
    draw_bytes_bar,
)

_COMPRESS_EXTS = (
    ('.tar.gz',   'gz'),
    ('.tgz',      'gz'),
    ('.tar.bz2',  'bz2'),
    ('.tbz2',     'bz2'),
    ('.tar.xz',   'xz'),
    ('.txz',      'xz'),
    ('.tar.lzma', 'xz'),
    ('.tlzma',    'xz'),
    ('.tar',      ''),
)

_UNSUPPORTED_EXTS = ('.tar.zst', '.tzst', '.tar.lz4', '.tar.lz')

_COMPRESSION_ARG_MAP = {
    'gzip':  'gz',
    'bzip2': 'bz2',
    'xz':    'xz',
    'none':  '',
}


def _compression_mode(filename: str) -> str:
    """Return the tarfile compression suffix for *filename*'s extension."""
    low = filename.lower()
    for ext, comp in _COMPRESS_EXTS:
        if low.endswith(ext):
            return comp
    for ext in _UNSUPPORTED_EXTS:
        if low.endswith(ext):
            raise ValueError(f"Compression format '{ext}' is not supported.")
    return ''


def _iter_entries(root: str, arcroot: str):
    """Yield *(src_path, arcname)* for every entry under *root* in sorted order."""
    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, topdown=True
    ):
        rel = os.path.relpath(dirpath, root)
        dirnames.sort()
        arc_dir = arcroot if rel == '.' else os.path.join(arcroot, rel)

        yield (dirpath, arc_dir)

        i = 0
        while i < len(dirnames):
            d = dirnames[i]
            if os.path.islink(os.path.join(dirpath, d)):
                yield (os.path.join(dirpath, d), os.path.join(arc_dir, d))
                dirnames.pop(i)
            else:
                i += 1

        for fname in sorted(filenames):
            yield (os.path.join(dirpath, fname), os.path.join(arc_dir, fname))


class _ReadCounter:
    """File wrapper that calls on_read(n) with the byte count after each read."""

    def __init__(self, fh, on_read):
        self._fh = fh
        self._on_read = on_read

    def read(self, n=-1):
        data = self._fh.read(n)
        if data:
            self._on_read(len(data))
        return data

    def __getattr__(self, name):
        return getattr(self._fh, name)


def _add_path(
    tf: tarfile.TarFile, src: str, arcname: str,
    on_read=None,
) -> None:
    """Add *src* to *tf* as *arcname*, stripping ownership info."""
    try:
        st = os.lstat(src)
    except OSError:
        return
    m = st.st_mode
    if (stat.S_ISBLK(m) or stat.S_ISCHR(m)
            or stat.S_ISFIFO(m) or stat.S_ISSOCK(m)):
        return

    try:
        info = tf.gettarinfo(src, arcname=arcname)
    except OSError:
        return
    info.uid = 0
    info.gid = 0
    info.uname = ''
    info.gname = ''
    if stat.S_ISREG(m):
        try:
            with open(src, 'rb') as fh:
                tf.addfile(info, _ReadCounter(fh, on_read) if on_read else fh)
        except OSError:
            pass
    else:
        tf.addfile(info)


def _fix_permissions(rootfs_dir: str) -> None:
    """Ensure all dirs and files in *rootfs_dir* are readable by owner."""
    for dirpath, _dirs, files in os.walk(rootfs_dir):
        with contextlib.suppress(OSError):
            os.chmod(
                dirpath,
                os.stat(dirpath).st_mode | stat.S_IRUSR | stat.S_IXUSR,
            )
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            try:
                fst = os.lstat(fpath)
                if stat.S_ISREG(fst.st_mode):
                    mode = fst.st_mode
                    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                        os.chmod(fpath, mode | stat.S_IRUSR | stat.S_IXUSR)
                    else:
                        os.chmod(fpath, mode | stat.S_IRUSR)
            except OSError:
                pass


def command_backup(args) -> None:
    """Archive an installed container to a tar file or stdout."""
    container_name = args.container_name
    output_path = getattr(args, "output", None)
    compression_arg = getattr(args, "compression", None)
    verbose = getattr(args, "verbose", False)

    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    manifest_path = container_manifest(container_name)

    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' does not exist.")
        sys.exit(1)

    if output_path is not None and not output_path:
        crit_error("output file path cannot be empty.")
        sys.exit(1)

    if output_path:
        if os.path.isdir(output_path):
            crit_error(f"cannot write to '{output_path}' because this path is a directory.")
            sys.exit(1)
        if os.path.isfile(output_path):
            crit_error(f"file '{output_path}' already exists. Please specify a different name.")
            sys.exit(1)
        if compression_arg is not None:
            compression = _COMPRESSION_ARG_MAP[compression_arg]
        else:
            try:
                compression = _compression_mode(output_path)
            except ValueError as exc:
                crit_error(str(exc).lower())
                sys.exit(1)
    else:
        if sys.stdout.isatty():
            crit_error("archive data cannot be printed to console. Please specify --output.")
            sys.exit(1)
        compression = (
            _COMPRESSION_ARG_MAP[compression_arg]
            if compression_arg is not None
            else ''
        )

    with ContainerLock(container_name, exclusive=False, command="backup"):
        # 1. Active sessions safety check
        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            crit_error(f"Cannot backup container '{container_name}': It has active sessions (PIDs: {active_pids}).")
            sys.exit(1)

        # 2. Mount safety check: ensure no active mounts exist under rootfs
        mounts = mount_manager.get_active_mounts(rootfs_dir)
        if mounts:
            crit_error(f"Cannot backup container '{container_name}': Active mounts detected under rootfs: {mounts}.")
            sys.exit(1)

        _run_backup(
            container_name, rootfs_dir, manifest_path,
            output_path, compression, verbose,
        )


def _run_backup(
    container_name, rootfs_dir, manifest_path,
    output_path, compression, verbose,
):
    log_info(f"Backing up '{container_name}'...")

    if output_path:
        log_info(f"Will write backup data to '{output_path}'.")
    else:
        log_info("Will write backup data to stdout.")

    log_info("Fixing file permissions in rootfs...")
    _fix_permissions(rootfs_dir)

    arc_prefix = container_name
    entries = []
    if os.path.isfile(manifest_path):
        entries.append((manifest_path, os.path.join(arc_prefix, "manifest.json")))
    entries.extend(_iter_entries(rootfs_dir, os.path.join(arc_prefix, "rootfs")))

    total_size = 0
    for src, _arc in entries:
        try:
            st = os.lstat(src)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            total_size += st.st_size

    done_size = 0
    log_info("Archiving the container...")

    _last_shown = 0

    def _draw_bar() -> None:
        nonlocal _last_shown
        draw_bytes_bar(done_size, total_size)
        _last_shown = done_size

    def _on_read(n: int) -> None:
        nonlocal done_size
        done_size += n
        if done_size - _last_shown >= REDRAW_THRESHOLD_BYTES:
            _draw_bar()

    def _on_entry(arc: str) -> None:
        if verbose:
            log_info(f"Adding: '{arc}'")
        _draw_bar()

    try:
        tar_mode = f'w:{compression}' if output_path else f'w|{compression}'
        if output_path:
            tf = tarfile.open(output_path, mode=tar_mode)  # type: ignore[call-overload]  # noqa: SIM115
        else:
            tf = tarfile.open(fileobj=sys.stdout.buffer, mode=tar_mode)  # type: ignore[call-overload]  # noqa: SIM115
        with tf:
            for src, arc in entries:
                _add_path(tf, src, arc, on_read=_on_read)
                _on_entry(arc)

        clear_bar()
        log_info("Finished backing up.")

    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        if output_path:
            with contextlib.suppress(OSError):
                os.remove(output_path)
        sys.exit(1)
    except (OSError, tarfile.TarError) as exc:
        clear_bar()
        log_error(f"Failed to create backup archive: {exc}")
        if output_path:
            with contextlib.suppress(OSError):
                os.remove(output_path)
        sys.exit(1)
