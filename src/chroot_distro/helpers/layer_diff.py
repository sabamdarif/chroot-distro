import contextlib
import gzip
import hashlib
import io
import os
import stat
import tarfile
import typing
import zlib

from chroot_distro.progress import (
    clear_bar,
    draw_bytes_bar,
    progress_active,
)

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


def diff_snapshots(
    before: dict[str, tuple[typing.Any, ...]],
    after: dict[str, tuple[typing.Any, ...]]
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
    out_path: str,
    total_uncompressed: int,
    populate: typing.Callable[[tarfile.TarFile], None]
) -> tuple[str, int, str]:
    """Run `populate(tf)` against a tarfile.TarFile that streams its
    output through a hash+gzip+hash pipeline into `out_path`.

    `total_uncompressed` is the expected number of tar payload bytes
    (sum of regular-file sizes) used only for the progress bar.
    Headers and padding add a small constant overhead beyond this.

    Returns (digest, gzipped_size, diff_id).
    """
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"

    digest_h = hashlib.sha256()
    diff_id_h = hashlib.sha256()
    show, clear = _make_progress_callback(total_uncompressed)

    out_fh = None
    gz = None
    tf = None
    digest_tee = None
    try:
        out_fh = open(tmp, "wb")  # noqa: SIM115
        digest_tee = _ProgressHashTee(out_fh, digest_h)
        gz = gzip.GzipFile(fileobj=digest_tee, mode="wb", mtime=0)
        diff_id_tee = _ProgressHashTee(gz, diff_id_h, on_progress=show)
        tf = tarfile.open(fileobj=diff_id_tee, mode="w|")  # type: ignore[call-overload]  # noqa: SIM115
        populate(tf)
        tf.close()
        tf = None
        gz.close()
        gz = None
        out_fh.flush()
        out_fh.close()
        out_fh = None
        clear()
        os.replace(tmp, out_path)
    except BaseException:
        clear()
        for handle in (tf, gz, out_fh):
            if handle is not None:
                with contextlib.suppress(OSError):
                    handle.close()
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
            kind = entry.get("kind")
            if kind == "content":
                total += len(entry.get("data", b""))
            elif kind == "file":
                with contextlib.suppress(OSError):
                    total += os.path.getsize(entry["src"])
        else:
            try:
                st = os.lstat(entry)
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
            except OSError:
                pass

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
        except OSError:
            pass
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
        except OSError:
            pass
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
        if kind == "content":
            data = entry["data"]
            tinfo = tarfile.TarInfo(arcname)
            tinfo.type = tarfile.REGTYPE
            tinfo.size = len(data)
            tinfo.mode = entry.get("mode", 0o644)
            tinfo.mtime = entry.get("mtime", 0)
            tinfo.uid = entry.get("uid", 0)
            tinfo.gid = entry.get("gid", 0)
            tf.addfile(tinfo, io.BytesIO(data))
            return
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
            entry.get("mode", stat.S_IMODE(st.st_mode))
            if isinstance(entry, dict) else stat.S_IMODE(st.st_mode)
        )
        tinfo.mtime = int(st.st_mtime)
        tinfo.uid = (entry.get("uid", 0) if isinstance(entry, dict) else 0)
        tinfo.gid = (entry.get("gid", 0) if isinstance(entry, dict) else 0)
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
            entry.get("mode", stat.S_IMODE(st.st_mode))
            if isinstance(entry, dict) else stat.S_IMODE(st.st_mode)
        )
        tinfo.mtime = int(st.st_mtime)
        tinfo.uid = (entry.get("uid", 0) if isinstance(entry, dict) else 0)
        tinfo.gid = (entry.get("gid", 0) if isinstance(entry, dict) else 0)
        with open(src_path, "rb") as fobj:
            tf.addfile(tinfo, fobj)
