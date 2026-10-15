# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Export one built platform as a plain rootfs: a tarball, or a directory.

This is `build --export`, distinct from `--output`, which writes the OCI image
(manifest, config, layer blobs). What lands here is the filesystem alone: the
layers read back out of the content-addressed cache and applied into a scratch
tree through the same extractor an install uses, whiteouts resolved and all, so
the export is exactly the rootfs the image describes rather than the documents
about it.

`write_rootfs_tar` streams that tree out through the numeric-ownership walk
`commands/backup.py` uses, so a non-root image survives the round trip and
device nodes are dropped (a session recreates /dev itself). The arcnames sit at
the archive root with no wrapper directory, so the tar is a plain rootfs tar
the way `type=local`/`type=tar` mean one, not a backup.

`export_local_dir` copies the same tree out to a directory the caller owns.
"""

import contextlib
import itertools
import os
import stat
import sys
import typing

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.commands.backup import _add_path, _iter_entries
from chroot_distro.helpers.docker.cache import layer_cache_path
from chroot_distro.helpers.docker.layers import apply_layer
from chroot_distro.progress import REDRAW_THRESHOLD_BYTES, clear_bar, draw_bytes_bar

_TAR_MODES = {
    ".tar": "w",
    ".tar.gz": "w:gz",
    ".tgz": "w:gz",
    ".tar.bz2": "w:bz2",
    ".tbz2": "w:bz2",
    ".tar.xz": "w:xz",
    ".txz": "w:xz",
    ".tar.zst": "w:zst",
    ".tar.zstd": "w:zst",
}


_export_seq = itertools.count()


def _detect_tar_mode(path: str) -> str:
    """The tarfile write mode for a path's extension, plain tar when none is known."""
    low = path.lower()
    # Order matters: try longer suffixes first.
    for ext in sorted(_TAR_MODES, key=len, reverse=True):
        if low.endswith(ext):
            return _TAR_MODES[ext]
    return "w"


def _materialize(layers: list[dict[str, typing.Any]], rootfs_fd: int) -> None:
    """Rebuild the rootfs *layers* describe under *rootfs_fd*.

    The blobs come straight out of the cache the build wrote them into, so the
    tree is exactly what the image holds; a blob missing from the cache raises
    rather than yielding a truncated rootfs.
    """
    for layer in layers:
        digest = layer["digest"]
        layer_path = layer_cache_path(digest)
        if not os.path.isfile(layer_path):
            raise RuntimeError(
                f"Layer blob {digest} is missing from the cache; cannot rebuild the rootfs."
            )
        apply_layer(layer_path, rootfs_fd)


@contextlib.contextmanager
def _materialized_rootfs(
    layers: list[dict[str, typing.Any]],
    scratch_path: str,
    scratch_fd: int,
    tag: str,
):
    """Yield (path, fd) of a scratch tree holding the rootfs *layers* describe.

    Made under the build's own scratch root, so teardown removes it with the
    rest; the tag only names the subdirectory, and an itertools count keeps two
    exports of one image from colliding on it. The path is the real one
    (*scratch_path* joined with the name), since the tar walk addresses members
    by name, and the fd is what the layer application writes through.
    """
    name = f"export-{next(_export_seq)}-{tag.replace('/', '_')}"
    os.mkdir(name, 0o700, dir_fd=scratch_fd)
    root_fd = dirfd.opendir_at(scratch_fd, name)
    try:
        _materialize(layers, root_fd)
        yield os.path.join(scratch_path, name), root_fd
    finally:
        os.close(root_fd)


def write_rootfs_tar(
    out_path: str,
    layers: list[dict[str, typing.Any]],
    scratch_path: str,
    scratch_fd: int,
    tag: str,
) -> None:
    """Write the rootfs *layers* describe as a plain tarball at *out_path*.

    Packed into the descriptor `atomic_write` staged, for the reason
    `oci_writer.write_oci_archive` gives: the output directory is the user's,
    and a reopened temporary can be swapped before the rename publishes it.
    """
    if not layers:
        raise RuntimeError("No layers to export; cannot write a rootfs tarball.")

    mode = _detect_tar_mode(out_path)
    with _materialized_rootfs(layers, scratch_path, scratch_fd, tag) as (rootfs_path, _fd):
        entries = list(_iter_entries(rootfs_path, ""))
        total_size = 0
        for src, _arc in entries:
            try:
                st = os.lstat(src)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total_size += st.st_size

        done_size = 0
        _last_shown = 0

        def _on_read(n: int) -> None:
            nonlocal done_size, _last_shown
            done_size += n
            if done_size - _last_shown >= REDRAW_THRESHOLD_BYTES:
                draw_bytes_bar(done_size, total_size)
                _last_shown = done_size

        out_abs = os.path.abspath(out_path)
        with (
            atomic_write(out_abs, binary_mode=True) as tmp_fh,
            tarfile.open(fileobj=tmp_fh, mode=mode) as tf,  # type: ignore[call-overload]
        ):
            dropped = 0
            for src, arc in entries:
                if not _add_path(tf, src, arc, on_read=_on_read):
                    dropped += 1
        clear_bar()
        if dropped:
            plural = "entry" if dropped == 1 else "entries"
            raise RuntimeError(f"{dropped} {plural} could not be archived.")


def export_local_dir(
    dest_dir: str,
    layers: list[dict[str, typing.Any]],
    scratch_path: str,
    scratch_fd: int,
    tag: str,
) -> None:
    """Copy the rootfs *layers* describe into the directory *dest_dir*.

    *dest_dir* must not exist yet, the caller refuses an existing one, so the
    copy lands in a tree made here rather than merging into one the user pointed
    at.
    """
    if not layers:
        raise RuntimeError("No layers to export; cannot copy out a rootfs.")

    with _materialized_rootfs(layers, scratch_path, scratch_fd, tag) as (rootfs_path, _fd):
        os.makedirs(dest_dir, mode=0o755)
        # Reopen by path: the materialized descriptor's offset sits at the end
        # after the layer walk, and a scandir off it would see an empty tree.
        src_fd = dirfd.opendir(rootfs_path)
        dest_fd = dirfd.opendir(dest_dir)
        try:
            dirfd.copy_tree_at(src_fd, dest_fd)
        finally:
            os.close(src_fd)
            os.close(dest_fd)
