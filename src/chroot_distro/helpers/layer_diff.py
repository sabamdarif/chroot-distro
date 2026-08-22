import contextlib
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

from chroot_distro.progress import (
    clear_bar,
    draw_bytes_bar,
    progress_active,
)

log = logging.getLogger(__name__)

_CRC_CHUNK = 65536


def _file_crc32(path: str) -> int:
    """Return the zlib.crc32 of `path`'s content as an unsigned int.

    A 32-bit CRC is fast (C-implemented in zlib, ~GB/s) and good enough
    to distinguish content as long as we already trust the cheap (size,
    mtime) check to flag obvious modifications.

    Returns 0xFFFFFFFF on read failure; that value collides with a
    legitimate CRC only with probability 1/2^32, and the file is going
    to be re-snapshotted on the next RUN anyway.
    """
    crc = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CRC_CHUNK)
                if not chunk:
                    break
                crc = zlib.crc32(chunk, crc)
    except OSError:
        return 0xFFFFFFFF
    return crc & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Snapshot / diff
# ---------------------------------------------------------------------------


def snapshot(rootfs: str) -> dict[str, tuple[typing.Any, ...]]:
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
    cases the (size, mtime) pair can't catch on its own — namely
    `touch -r`-style mtime preservation and sub-second double-writes.
    """
    state: dict[str, tuple[typing.Any, ...]] = {}
    stack = [(rootfs, "")]
    while stack:
        dirpath, rel_prefix = stack.pop()
        try:
            it = os.scandir(dirpath)
        except OSError:
            continue
        try:
            for entry in it:
                name = entry.name
                rel = rel_prefix + name if rel_prefix else name
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                mode = st.st_mode
                if stat.S_ISLNK(mode):
                    with contextlib.suppress(OSError):
                        state[rel] = ("symlink", os.readlink(entry.path))
                elif stat.S_ISDIR(mode):
                    state[rel] = ("dir", stat.S_IMODE(mode))
                    stack.append((entry.path, rel + "/"))
                elif stat.S_ISREG(mode):
                    state[rel] = (
                        "file",
                        st.st_size,
                        st.st_mtime_ns,
                        stat.S_IMODE(mode),
                        _file_crc32(entry.path),
                    )
                # Other types intentionally skipped.
        finally:
            it.close()
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


# ---------------------------------------------------------------------------
# Streaming layer-tar writer + progress bar
# ---------------------------------------------------------------------------


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
    """
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"

    digest_h = hashlib.sha256()
    diff_id_h = hashlib.sha256()
    show, clear = _make_progress_callback(total_uncompressed)

    digest_tee: _ProgressHashTee | None = None
    try:
        with open(tmp, "wb") as out_fh:
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
            out_fh.flush()
        clear()
        os.replace(tmp, out_path)
    except BaseException:
        clear()
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise

    assert digest_tee is not None
    return (
        "sha256:" + digest_h.hexdigest(),
        digest_tee.count,
        "sha256:" + diff_id_h.hexdigest(),
    )


# ---------------------------------------------------------------------------
# Public layer writers
# ---------------------------------------------------------------------------


def write_layer_tar(
    rootfs: str,
    paths_to_pack: list[str],
    deleted: list[str],
    out_path: str,
    opaque_dirs: typing.Iterable[str] = (),
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
    """
    sorted_paths = sorted(paths_to_pack)
    total = 0
    for rel in sorted_paths:
        full = os.path.join(rootfs, rel)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            total += st.st_size

    def _populate(tf: tarfile.TarFile) -> None:
        for rel in sorted_paths:
            _add_entry(tf, rootfs, rel)
        for wh in _whiteout_paths(deleted, opaque_dirs):
            _add_whiteout(tf, wh)

    return _pack_stream(out_path, total, _populate)


def write_files_layer(file_map: dict[str, typing.Any], out_path: str) -> tuple[str, int, str]:
    """Pack a {arcname → entry} mapping into a gzipped OCI layer."""
    sorted_items = sorted(file_map.items())

    # Pre-compute total content bytes for the progress bar.
    total = 0
    for _arcname, entry in sorted_items:
        if isinstance(entry, dict):
            if entry.get("kind") == "file":
                with contextlib.suppress(OSError):
                    total += os.path.getsize(entry["src"])
        else:
            try:
                st = os.lstat(entry)
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
            except OSError as exc:
                log.debug("Failed to lstat %s for size estimation: %s", entry, exc)

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
        for arcname, entry in sorted_items:
            _add_file_map_entry(tf, arcname, entry)

    return _pack_stream(out_path, total, _populate)


# ---------------------------------------------------------------------------
# Per-entry tar emitters
# ---------------------------------------------------------------------------


def _add_entry(tf: tarfile.TarFile, rootfs: str, rel: str) -> None:
    """Add the on-disk entry at <rootfs>/<rel> to the tar by arcname=rel."""
    full = os.path.join(rootfs, rel)
    try:
        st = os.lstat(full)
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
            target = os.readlink(full)
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
        tinfo.type = tarfile.REGTYPE
        tinfo.size = st.st_size
        try:
            with open(full, "rb") as fobj:
                tf.addfile(tinfo, fobj)
        except OSError as exc:
            log.warning("Failed to add file %s to tar: %s", rel, exc)
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


def _add_file_map_entry(tf: tarfile.TarFile, arcname: str, entry: typing.Any) -> None:
    if isinstance(entry, dict):
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
        # There is deliberately no in-memory "content" kind: a file_map
        # covers a whole instruction, so every entry's bytes would be live at
        # once. Content that is not already a file is spooled to one (see
        # build_engine.copy_step._spool_entry).
        if kind == "file":
            src_path = entry["src"]
        else:
            return
    else:
        src_path = entry

    try:
        st = os.lstat(src_path)
    except OSError:
        return

    if stat.S_ISDIR(st.st_mode):
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.DIRTYPE
        tinfo.mode = (
            entry.get("mode", stat.S_IMODE(st.st_mode)) if isinstance(entry, dict) else stat.S_IMODE(st.st_mode)
        )
        tinfo.mtime = int(st.st_mtime)
        tinfo.uid = entry.get("uid", 0) if isinstance(entry, dict) else 0
        tinfo.gid = entry.get("gid", 0) if isinstance(entry, dict) else 0
        tf.addfile(tinfo)
    elif stat.S_ISLNK(st.st_mode):
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.SYMTYPE
        tinfo.linkname = os.readlink(src_path)
        tinfo.size = 0
        tinfo.mode = stat.S_IMODE(st.st_mode)
        tinfo.mtime = int(st.st_mtime)
        tf.addfile(tinfo)
    elif stat.S_ISREG(st.st_mode):
        tinfo = tarfile.TarInfo(arcname)
        tinfo.type = tarfile.REGTYPE
        tinfo.size = st.st_size
        tinfo.mode = (
            entry.get("mode", stat.S_IMODE(st.st_mode)) if isinstance(entry, dict) else stat.S_IMODE(st.st_mode)
        )
        tinfo.mtime = int(st.st_mtime)
        tinfo.uid = entry.get("uid", 0) if isinstance(entry, dict) else 0
        tinfo.gid = entry.get("gid", 0) if isinstance(entry, dict) else 0
        with open(src_path, "rb") as fobj:
            tf.addfile(tinfo, fobj)
