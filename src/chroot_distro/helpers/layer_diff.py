# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Decide what a build step changed, and pack the change into an OCI layer.

Two ways of asking what changed, and they are not interchangeable. `snapshot` walks a
live rootfs and fingerprints a file as (size, mtime_ns, mode, crc32), where the CRC is
only ever a tie-breaker: tuple equality short-circuits on size and mtime, so the hash is
read for the cases those miss, a `touch -r` and a sub-second double write.
`baseline_from_layers` instead replays cached layer tars, and a tar preserves nothing
finer than a size and a symlink target, which is why `diff_against_baseline` compares
conservatively. Handing a replayed baseline to `diff_snapshots` would report the whole
image as modified.

A deletion leaves no file to pack, so it becomes an OCI whiteout: `.wh.<name>` for one
entry, `.wh..wh..opq` for a directory that survived with its contents gone. The replay
reads the same two markers back.

Descriptor discipline is most of this file's length, and the reason is that its output is
published: `push` uploads a layer to a registry, so a host file that finds its way in
leaves the machine. Every walk carries directory descriptors instead of names, `_ParentFds`
re-walks a packed entry's parent with O_NOFOLLOW, `MapSources` re-walks the tree a
file_map entry named, and a regular file's size comes off the fstat of the descriptor
about to be read rather than an earlier lstat of the name, because tarfile writes exactly
`tinfo.size` bytes from what it is handed. The window this closes is real: a process an
earlier RUN left running, which off Termux nothing kills, can replace a component between
the walk and the pack. One `_ParentFds` also spans both the size pre-pass and the pack,
so the progress denominator and the packed bytes come out of the same directories.

`_pack_stream` computes both digests in a single pass, the layer digest over the
compressed bytes and the diff_id over the uncompressed tar, and stages through
`atomic_write` because a layer's filename follows from the stage and layer index and is
therefore guessable. Entries are written with uid/gid 0 and gzip mtime 0 so the same tree
packs to the same bytes.

The baseline cache is keyed by the ordered layer digests and is entirely best-effort: a
valid entry means the layer blobs need not be present at all, which is what makes a diff
still work after `clear-cache`.
"""

import contextlib
import errno
import gzip
import hashlib
import json
import logging
import os
import stat
import sys
import typing
import zlib

if sys.version_info >= (3, 14):
    import tarfile

    from compression import zstd
else:
    from backports import zstd
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.progress import (
    clear_bar,
    draw_bytes_bar,
    progress_active,
)

log = logging.getLogger(__name__)

_CRC_CHUNK = 65536


def _file_crc32(dir_fd: int, name: str) -> int:
    """Return the zlib.crc32 of *name*'s content as an unsigned int.

    A 32-bit CRC is fast (C-implemented in zlib, ~GB/s) and good enough
    to distinguish content as long as we already trust the cheap (size,
    mtime) check to flag obvious modifications.

    Opened as (dir_fd, name) through open_regular_at, so the file whose
    content is read is the one the walk lstat'ed a moment ago, whatever a
    process left over from an earlier RUN does to the name in between.

    Returns 0xFFFFFFFF on read failure; that value collides with a
    legitimate CRC only with probability 1/2^32, and the file is going
    to be re-snapshotted on the next RUN anyway.
    """
    crc = 0
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, name, os.O_RDONLY)
    except OSError:
        return 0xFFFFFFFF
    try:
        with open(fd, "rb", closefd=False) as fh:
            while True:
                chunk = fh.read(_CRC_CHUNK)
                if not chunk:
                    break
                crc = zlib.crc32(chunk, crc)
    except OSError:
        return 0xFFFFFFFF
    finally:
        os.close(fd)
    return crc & 0xFFFFFFFF


class MapSources:
    """The directories a file_map's "file" entries are read out of.

    An entry does not name a path to open. It names the *tree* it was found in
    (the build context, another stage's rootfs, an image pulled for
    COPY --from, the build's own spool) and the components below it, and both
    consumers (copy_step's materialiser and the packer below) re-walk those
    components from the root with O_NOFOLLOW before reading a byte.

    That is the difference between deciding where a source is and reading it.
    COPY/ADD enumerates a whole instruction first and consumes the map
    afterwards, twice, so between the lstat that recorded an entry and the read
    that packs it a component can be replaced with a symlink, by a process an
    earlier RUN left running, which off Termux nothing kills, or simply by
    whoever else can write the tree. Resolving the name again then reads
    whatever it leads to now, and a layer is the worst place for a host file to
    turn up: `push` uploads it to a registry.

    One directory at a time is cached, which covers a whole directory's worth of
    entries: both consumers walk the map in sorted-arcname order and an arcname
    follows the layout of the source it came from.

    An entry that also carries a "root_fd" was recorded against a tree the
    enumeration had pinned (a build stage's rootfs, the ADD spool), and the
    walk then starts from that descriptor rather than resolving the root's
    name a second time.
    """

    def __init__(self) -> None:
        self._key: tuple[str, int | None, tuple[str, ...]] | None = None
        self._fd: int | None = None

    def open(self, entry: dict[str, typing.Any]) -> tuple[int, os.stat_result]:
        """Open *entry*'s source as a regular file. Returns (fd, stat).

        Raises OSError when the walk refuses a component or the entry is no
        longer a regular file; the caller owns the descriptor. A "file" entry
        without a root and rel is a programming error, not a filesystem one, and
        raises KeyError rather than quietly reading a path.
        """
        root = entry["root"]
        root_fd = entry.get("root_fd")
        rel = tuple(entry["rel"])
        if not rel:
            raise OSError(errno.EINVAL, "source entry names no file", root)
        key = (root, root_fd, rel[:-1])
        if key != self._key:
            self.close()
            if root_fd is None:
                own_fd = dirfd.opendir(root)
                try:
                    fd = dirfd.descend_at(own_fd, rel[:-1])
                finally:
                    os.close(own_fd)
            else:
                fd = dirfd.descend_at(root_fd, rel[:-1]) if rel[:-1] else dirfd.reopen(root_fd)
            self._fd, self._key = fd, key
        assert self._fd is not None
        return dirfd.open_regular_at(self._fd, rel[-1], os.O_RDONLY)

    def close(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
        self._fd, self._key = None, None

    def __enter__(self) -> "MapSources":
        return self

    def __exit__(self, *_exc: typing.Any) -> None:
        self.close()


class _ParentFds:
    """Directory descriptors for the parents of the entries being packed.

    Every rel handed to _add_entry came off snapshot()'s own walk, so its
    parents were real directories then. Between then and the pack a process an
    earlier RUN left running can replace one with a symlink, and naming the
    entry then reads through it. A layer is the worst place for that: `push`
    uploads it to a registry.

    So each parent is re-walked from the rootfs descriptor with O_NOFOLLOW and
    the entry is addressed as (dir_fd, name). The rels arrive sorted, so caching
    the last parent covers a whole directory's worth of entries and the walk
    costs about one openat apiece.

    *rootfs_fd* is the rootfs when the caller has pinned it, so even the root
    of the walk is an inode rather than a name.
    """

    def __init__(self, rootfs: str, *, rootfs_fd: int | None = None) -> None:
        self._root_fd = dirfd.reopen(rootfs_fd) if rootfs_fd is not None else dirfd.opendir(rootfs)
        self._rel: str | None = None
        self._fd: int | None = None
        self._owned = False

    def open(self, parent_rel: str) -> int | None:
        """Return a descriptor for *parent_rel* under the rootfs, or None."""
        if self._fd is not None and parent_rel == self._rel:
            return self._fd
        self._release()
        self._rel = parent_rel
        if not parent_rel:
            self._fd, self._owned = self._root_fd, False
            return self._fd
        fd, owned = self._root_fd, False
        for comp in parent_rel.split("/"):
            try:
                nxt = dirfd.opendir_at(fd, comp)
            except OSError:
                if owned:
                    os.close(fd)
                self._fd, self._owned = None, False
                return None
            if owned:
                os.close(fd)
            fd, owned = nxt, True
        self._fd, self._owned = fd, owned
        return fd

    def _release(self) -> None:
        if self._owned and self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
        self._fd, self._owned = None, False

    def close(self) -> None:
        self._release()
        with contextlib.suppress(OSError):
            os.close(self._root_fd)


def snapshot(rootfs: str, *, rootfs_fd: int | None = None) -> dict[str, tuple[typing.Any, ...]]:
    """Return {rel_path: fingerprint_tuple} for every entry under rootfs.

    Tuple kinds:
        ("dir", mode)
        ("symlink", target)
        ("file", size, mtime_ns, mode, crc32)
    Block/char devices, FIFOs, sockets, etc. are skipped silently.

    Comparison semantics (via tuple equality during `diff_snapshots`):
    Python's tuple `==` short-circuits at the first differing field,
    so if `size` or `mtime_ns` between the before- and after-snapshot
    entries already differ, the file is flagged modified without
    consulting CRC32 at all. CRC32 is the tie-breaker for the corner
    cases the (size, mtime) pair can't catch on its own, namely
    `touch -r`-style mtime preservation and sub-second double-writes.

    The walk carries directory descriptors rather than paths: os.scandir on a
    name descends whatever it resolves to now, and the CRC then opened that name
    a second time, so a process an earlier RUN left running could have a host
    file's content decide a fingerprint.

    *rootfs_fd* is the rootfs when the caller has pinned it. A RUN step's two
    snapshots straddle the step, so the name they would resolve is one the
    step itself had the run of; starting from the descriptor means both walks
    describe the same tree the step was given.

    Frame layout: [fd, None, pending names, rel prefix, owned].
    """
    state: dict[str, tuple[typing.Any, ...]] = {}
    try:
        root_fd = dirfd.reopen(rootfs_fd) if rootfs_fd is not None else dirfd.opendir(rootfs)
    except OSError:
        return state

    stack: list[dirfd._Frame] = [[root_fd, None, None, "", True]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, pending, rel_prefix, owned = frame
            if pending is None:
                try:
                    pending = frame[2] = dirfd.listdir_at(fd)
                except OSError:
                    pending = frame[2] = []
            if not pending:
                levels.pop()
                if owned:
                    os.close(fd)
                continue

            name = pending.pop()
            rel = rel_prefix + name if rel_prefix else name
            try:
                st = dirfd.lstat_at(fd, name)
            except OSError:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                with contextlib.suppress(OSError):
                    state[rel] = ("symlink", os.readlink(name, dir_fd=fd))
            elif stat.S_ISDIR(mode):
                state[rel] = ("dir", stat.S_IMODE(mode))
                try:
                    sub = dirfd.opendir_at(fd, name)
                except OSError:
                    continue
                levels.push([sub, None, None, rel + "/", True])
            elif stat.S_ISREG(mode):
                state[rel] = (
                    "file",
                    st.st_size,
                    st.st_mtime_ns,
                    stat.S_IMODE(mode),
                    _file_crc32(fd, name),
                )
            # Other types intentionally skipped.
    except BaseException:
        dirfd.close_frames(stack)
        raise
    return state


def baseline_from_layers(layer_paths: list[str]) -> dict[str, tuple[typing.Any, ...]]:
    """Reconstruct the image's path set by replaying cached layer tars.

    Reads each gzipped/zstd layer tar in order (oldest first) and applies its
    members and OCI whiteouts (``.wh.<name>`` deletes one entry,
    ``.wh..wh..opq`` clears a directory's contents) to build the set of paths
    the image shipped. Returns ``{rel_path: fingerprint}`` matching the tuple
    shapes produced by :func:`snapshot`, but with a coarse fingerprint:

        ("dir",)
        ("symlink", target)
        ("file", size)

    Only fields that survive tar round-tripping are recorded, so callers should
    compare conservatively (e.g. flag a file modified only when its size
    differs) to avoid false positives on mtime/crc that tars do not preserve.
    """
    state: dict[str, tuple[typing.Any, ...]] = {}
    for layer_path in layer_paths:
        try:
            tf = tarfile.open(layer_path, mode="r:*")
        except (OSError, tarfile.TarError):
            continue
        try:
            for member in tf:
                name = member.name.lstrip("./")
                if not name:
                    continue
                base = os.path.basename(name)
                parent = os.path.dirname(name)
                if base == ".wh..wh..opq":
                    prefix = (parent + "/") if parent else ""
                    for key in [k for k in state if parent and (k == parent or k.startswith(prefix))]:
                        if key != parent:
                            state.pop(key, None)
                    continue
                if base.startswith(".wh."):
                    target = base[len(".wh.") :]
                    deleted = (parent + "/" + target) if parent else target
                    prefix = deleted + "/"
                    for key in [k for k in state if k == deleted or k.startswith(prefix)]:
                        state.pop(key, None)
                    continue
                if member.isdir():
                    state[name] = ("dir",)
                elif member.issym() or member.islnk():
                    state[name] = ("symlink", member.linkname)
                elif member.isreg():
                    state[name] = ("file", member.size)
        finally:
            tf.close()
    return state


_BASELINE_CACHE_VERSION = 1


def _baseline_to_jsonable(baseline: dict[str, tuple[typing.Any, ...]]) -> dict[str, list]:
    """Convert baseline fingerprint tuples to JSON-serialisable lists."""
    return {path: list(fp) for path, fp in baseline.items()}


def _baseline_from_jsonable(data: dict[str, list]) -> dict[str, tuple[typing.Any, ...]]:
    """Convert loaded JSON lists back into fingerprint tuples."""
    return {path: tuple(fp) for path, fp in data.items()}


def baseline_cache_is_valid(cache_path: str, digests: list[str]) -> bool:
    """Return True if *cache_path* holds a baseline matching *digests*.

    When valid, :func:`cached_baseline_from_layers` can return the baseline
    without reading the layer tars at all, so the raw layer blobs are not
    required (e.g. after ``clear-cache`` wiped them).
    """
    cached = _read_baseline_cache(cache_path)
    return (
        cached is not None
        and cached.get("version") == _BASELINE_CACHE_VERSION
        and cached.get("digests") == digests
        and isinstance(cached.get("baseline"), dict)
    )


def cached_baseline_from_layers(
    layer_paths: list[str],
    digests: list[str],
    cache_path: str,
) -> dict[str, tuple[typing.Any, ...]]:
    """Return the image baseline, using *cache_path* to avoid re-reading layers.

    The cache is a JSON document keyed by the ordered list of layer
    *digests*. When the cached digest list matches, the stored baseline is
    returned directly; otherwise the baseline is rebuilt from the layer
    tars via :func:`baseline_from_layers` and the cache is refreshed.

    All cache I/O is best-effort: any error falls back to a full rebuild.
    """
    cached = _read_baseline_cache(cache_path)
    if cached is not None and cached.get("version") == _BASELINE_CACHE_VERSION and cached.get("digests") == digests:
        with contextlib.suppress(Exception):
            return _baseline_from_jsonable(cached["baseline"])

    baseline = baseline_from_layers(layer_paths)
    _write_baseline_cache(cache_path, digests, baseline)
    return baseline


def _read_baseline_cache(cache_path: str) -> dict | None:
    try:
        with open(cache_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _write_baseline_cache(
    cache_path: str,
    digests: list[str],
    baseline: dict[str, tuple[typing.Any, ...]],
) -> None:
    payload = {
        "version": _BASELINE_CACHE_VERSION,
        "digests": digests,
        "baseline": _baseline_to_jsonable(baseline),
    }
    tmp = cache_path + ".tmp"
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, cache_path)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def diff_against_baseline(
    baseline: dict[str, tuple[typing.Any, ...]], live: dict[str, tuple[typing.Any, ...]]
) -> tuple[list[str], list[str], list[str]]:
    """Compare a coarse layer *baseline* against a live rootfs snapshot.

    Returns (added, modified, deleted) sorted rel-path lists. A path is
    "modified" only when a comparable field actually differs (regular-file size
    or symlink target); mtime/crc are ignored because the baseline derived from
    tar members cannot preserve them.
    """
    added: list[str] = []
    modified: list[str] = []
    for path, live_fp in live.items():
        base_fp = baseline.get(path)
        if base_fp is None:
            added.append(path)
            continue
        live_kind = live_fp[0]
        base_kind = base_fp[0]
        if (
            live_kind != base_kind
            or (live_kind == "file" and live_fp[1] != base_fp[1])
            or (live_kind == "symlink" and live_fp[1] != base_fp[1])
        ):
            modified.append(path)
    deleted = [k for k in baseline if k not in live]
    return sorted(added), sorted(modified), sorted(deleted)


def diff_snapshots(
    before: dict[str, tuple[typing.Any, ...]], after: dict[str, tuple[typing.Any, ...]]
) -> tuple[list[str], list[str], list[str]]:
    """Return (added, modified, deleted), each a sorted list of rel paths."""
    added = []
    modified = []
    for k, v in after.items():
        if k not in before:
            added.append(k)
        elif before[k] != v:
            modified.append(k)
    deleted = [k for k in before if k not in after]
    return sorted(added), sorted(modified), sorted(deleted)


def _whiteout_paths(deleted: list[str], surviving_dirs: typing.Iterable[str]) -> list[str]:
    """Translate a list of deleted rel paths into OCI whiteout entries."""
    arcnames = []
    for rel in sorted(set(deleted)):
        parent = os.path.dirname(rel)
        basename = os.path.basename(rel)
        if parent:
            arcnames.append(parent + "/.wh." + basename)
        else:
            arcnames.append(".wh." + basename)
    for parent in sorted(surviving_dirs):
        if parent:
            arcnames.append(parent + "/.wh..wh..opq")
        else:
            arcnames.append(".wh..wh..opq")
    return arcnames


class _ProgressHashTee:
    """File-like wrapper. write() forwards bytes to `fh`, updates `hasher`,
    accumulates a byte counter, and triggers an optional progress
    callback throttled to once per 256 KiB or more.
    """

    def __init__(
        self,
        fh: typing.Any,
        hasher: typing.Any,
        on_progress: typing.Callable[[int], None] | None = None,
    ):
        self._fh = fh
        self._hasher = hasher
        self._on_progress = on_progress
        self.count = 0
        self._last_shown = 0

    def write(self, data: bytes | memoryview) -> int:
        if isinstance(data, memoryview):
            data = bytes(data)
        self._hasher.update(data)
        self.count += len(data)
        if self._on_progress is not None and self.count - self._last_shown >= 262144:
            self._last_shown = self.count
            self._on_progress(self.count)
        return int(self._fh.write(data))

    def flush(self) -> None:
        self._fh.flush()


def _make_progress_callback(total_size: int) -> tuple[typing.Callable[[int], None], typing.Callable[[], None]]:
    """Return a (callback, finaliser) pair for a stderr progress bar."""
    if not progress_active():
        return (lambda _done: None), (lambda: None)

    def _show(done: int) -> None:
        draw_bytes_bar(done, total_size, noun="packed")

    return _show, clear_bar


def _pack_stream(
    out_path: str, total_uncompressed: int, populate: typing.Callable[[tarfile.TarFile], None]
) -> tuple[str, int, str]:
    """Run `populate(tf)` against a tarfile.TarFile that streams its
    output through a hash + compression + hash pipeline into `out_path`.

    `total_uncompressed` is the expected number of tar payload bytes
    (sum of regular-file sizes) used only for the progress bar.
    Headers and padding add a small constant overhead beyond this.

    Returns (digest, compressed_size, diff_id).

    The write goes through atomic_write rather than a `<out_path>.tmp` of our
    own: the layer's name is derived from the stage and layer index, so that
    temporary is entirely predictable, and a symlink standing under it had the
    layer's bytes written through it, the link itself then published into the
    cache, where `push` reads it. atomic_write names its temporary
    unpredictably and creates it O_EXCL off a descriptor on the destination
    directory.
    """
    digest_h = hashlib.sha256()
    diff_id_h = hashlib.sha256()
    show, clear = _make_progress_callback(total_uncompressed)

    digest_tee: _ProgressHashTee | None = None
    try:
        with atomic_write(out_path, binary_mode=True) as out_fh:
            digest_tee = _ProgressHashTee(out_fh, digest_h)

            compressor: typing.Any
            if out_path.lower().endswith((".zst", ".zstd")):
                compressor = zstd.ZstdFile(typing.cast(typing.Any, digest_tee), mode="wb")
            else:
                compressor = gzip.GzipFile(fileobj=digest_tee, mode="wb", mtime=0)

            with compressor as cmp_file:
                diff_id_tee = _ProgressHashTee(cmp_file, diff_id_h, on_progress=show)
                with tarfile.open(fileobj=diff_id_tee, mode="w|") as tf:  # type: ignore[call-overload]
                    populate(tf)
        clear()
    except BaseException:
        clear()
        raise

    assert digest_tee is not None
    return (
        "sha256:" + digest_h.hexdigest(),
        digest_tee.count,
        "sha256:" + diff_id_h.hexdigest(),
    )


def write_layer_tar(
    rootfs: str,
    paths_to_pack: list[str],
    deleted: list[str],
    out_path: str,
    opaque_dirs: typing.Iterable[str] = (),
    *,
    rootfs_fd: int | None = None,
) -> tuple[str, int, str]:
    """Write a gzipped OCI layer to `out_path`.

    paths_to_pack: rel paths whose current state in `rootfs` should be
                   packed (the union of added + modified).
    deleted:       rel paths that disappeared since the snapshot.
    opaque_dirs:   rel paths of directories that survived but had all
                   children removed (emit `.wh..wh..opq` inside them).

    Returns (digest, size, diff_id) where digest is "sha256:<hex>" of
    the gzipped bytes, size is the gzipped byte count, and diff_id is
    "sha256:<hex>" of the uncompressed tar bytes.

    *rootfs_fd* is the rootfs when the caller has pinned it. The one
    _ParentFds is built before the size pre-pass and outlives it, so the
    sizes the progress bar is scaled to and the bytes that are packed come
    out of the same directories. The pre-pass used to lstat each entry by its
    joined path, which is a second resolve of every name in the layer.
    """
    sorted_paths = sorted(paths_to_pack)
    try:
        parents: _ParentFds | None = _ParentFds(rootfs, rootfs_fd=rootfs_fd)
    except OSError:
        parents = None

    total = 0
    if parents is not None:
        for rel in sorted_paths:
            parent_rel, _, name = rel.rpartition("/")
            dir_fd = parents.open(parent_rel)
            if dir_fd is None:
                continue
            try:
                st = dirfd.lstat_at(dir_fd, name)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += st.st_size

    def _populate(tf: tarfile.TarFile) -> None:
        for rel in sorted_paths:
            if parents is not None:
                _add_entry(tf, parents, rel)
        for wh in _whiteout_paths(deleted, opaque_dirs):
            _add_whiteout(tf, wh)

    try:
        return _pack_stream(out_path, total, _populate)
    finally:
        if parents is not None:
            parents.close()


def write_files_layer(file_map: dict[str, typing.Any], out_path: str) -> tuple[str, int, str]:
    """Pack a {arcname → entry} mapping into a gzipped OCI layer.

    Every entry is a dict describing what to write: a "dir", a "symlink", or a
    "file" naming the tree its bytes come from (see MapSources). The progress
    denominator is the size each "file" entry recorded when it was enumerated,
    so the pack stats nothing by name on the way in either.
    """
    sorted_items = sorted(file_map.items())

    # Pre-computed for the progress bar from what the enumeration saw.
    total = sum(entry.get("size", 0) for _arcname, entry in sorted_items if entry.get("kind") == "file")

    def _populate(tf: tarfile.TarFile) -> None:
        # Synthesise parent directory entries so the layer applies
        # cleanly even when intermediate dirs were not COPY'd.
        seen_dirs = set()
        for arcname, _ in sorted_items:
            parts = arcname.split("/")
            for k in range(1, len(parts)):
                dpath = "/".join(parts[:k])
                if dpath and dpath not in seen_dirs:
                    seen_dirs.add(dpath)
                    dinfo = tarfile.TarInfo(dpath)
                    dinfo.type = tarfile.DIRTYPE
                    dinfo.mode = 0o755
                    dinfo.mtime = 0
                    tf.addfile(dinfo)
        with MapSources() as sources:
            for arcname, entry in sorted_items:
                _add_file_map_entry(tf, arcname, entry, sources)

    return _pack_stream(out_path, total, _populate)


def _add_entry(tf: tarfile.TarFile, parents: _ParentFds, rel: str) -> None:
    """Add the on-disk entry at <rootfs>/<rel> to the tar by arcname=rel.

    *parents* supplies the descriptor of the entry's parent directory, so every
    one of the calls below names the entry relative to a directory the walk
    itself opened (see _ParentFds).
    """
    parent_rel, _, name = rel.rpartition("/")
    dir_fd = parents.open(parent_rel)
    if dir_fd is None:
        return
    try:
        st = dirfd.lstat_at(dir_fd, name)
    except OSError:
        return

    tinfo = tarfile.TarInfo(rel)
    tinfo.uid = 0
    tinfo.gid = 0
    tinfo.uname = ""
    tinfo.gname = ""
    tinfo.mtime = int(st.st_mtime)
    tinfo.mode = stat.S_IMODE(st.st_mode)

    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(name, dir_fd=dir_fd)
        except OSError:
            return

        try:
            tinfo.type = tarfile.SYMTYPE
            tinfo.linkname = target
            tinfo.size = 0
            tf.addfile(tinfo)
        except OSError as exc:
            log.warning("Failed to add symlink %s to tar: %s", rel, exc)
    elif stat.S_ISDIR(st.st_mode):
        tinfo.type = tarfile.DIRTYPE
        tinfo.size = 0
        tf.addfile(tinfo)
    elif stat.S_ISREG(st.st_mode):
        # The size comes off the fstat of the descriptor that is about to be
        # read, not off the earlier lstat of the name: those are two different
        # files the moment anything replaces the entry, and tarfile writes
        # exactly tinfo.size bytes from what it is handed.
        try:
            fd, fst = dirfd.open_regular_at(dir_fd, name, os.O_RDONLY)
        except OSError as exc:
            log.warning("Failed to add file %s to tar: %s", rel, exc)
            return
        try:
            tinfo.type = tarfile.REGTYPE
            tinfo.size = fst.st_size
            try:
                with open(fd, "rb", closefd=False) as fobj:
                    tf.addfile(tinfo, fobj)
            except OSError as exc:
                log.warning("Failed to add file %s to tar: %s", rel, exc)
        finally:
            os.close(fd)
    # Other types intentionally skipped (devices, FIFOs).


def _add_whiteout(tf: tarfile.TarFile, arcname: str) -> None:
    tinfo = tarfile.TarInfo(arcname)
    tinfo.type = tarfile.REGTYPE
    tinfo.size = 0
    tinfo.mode = 0o644
    tinfo.mtime = 0
    tinfo.uid = 0
    tinfo.gid = 0
    tinfo.uname = ""
    tinfo.gname = ""
    tf.addfile(tinfo)


def _add_file_map_entry(
    tf: tarfile.TarFile,
    arcname: str,
    entry: dict[str, typing.Any],
    sources: MapSources,
) -> None:
    """Add one file_map entry to the tar under *arcname*.

    A "file" entry's bytes come out of the descriptor *sources* opens for it,
    and its size off that descriptor's own fstat, never off an lstat of a name
    that is opened again afterwards. Its mode, uid and gid come from the entry
    (that is how COPY --chown and --chmod reach the layer) while its timestamp
    comes from the file, which is where ADD parks a spooled member's mtime.
    """
    kind = entry.get("kind")
    if kind == "symlink":
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.SYMTYPE
        tinfo.linkname = entry["target"]
        tinfo.size = 0
        tinfo.mode = entry.get("mode", 0o777)
        tinfo.mtime = entry.get("mtime", 0)
        tinfo.uid = entry.get("uid", 0)
        tinfo.gid = entry.get("gid", 0)
        tf.addfile(tinfo)
        return
    if kind == "dir":
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.DIRTYPE
        tinfo.mode = entry.get("mode", 0o755)
        tinfo.mtime = entry.get("mtime", 0)
        tinfo.uid = entry.get("uid", 0)
        tinfo.gid = entry.get("gid", 0)
        tf.addfile(tinfo)
        return
    # There is deliberately no in-memory "content" kind: a file_map covers a
    # whole instruction, so every entry's bytes would be live at once. Content
    # that is not already a file is spooled to one (see
    # build_engine.copy_step._spool_entry).
    if kind != "file":
        return

    try:
        fd, fst = sources.open(entry)
    except OSError as exc:
        log.warning("Failed to add file %s to tar: %s", arcname, exc)
        return
    try:
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.REGTYPE
        tinfo.size = fst.st_size
        tinfo.mode = entry.get("mode", stat.S_IMODE(fst.st_mode))
        tinfo.mtime = int(fst.st_mtime)
        tinfo.uid = entry.get("uid", 0)
        tinfo.gid = entry.get("gid", 0)
        with open(fd, "rb", closefd=False) as fobj:
            tf.addfile(tinfo, fobj)
    finally:
        os.close(fd)
