import contextlib
import errno
import fcntl
import hashlib
import json
import os
import time
import typing

from chroot_distro import dirfd, locking
from chroot_distro.atomic import atomic_write
from chroot_distro.constants import BASE_CACHE_DIR, RUNTIME_DIR

_INDEX_PATH = os.path.join(BASE_CACHE_DIR, "build_cache_index.json")
_INDEX_LOCK_PATH = _INDEX_PATH + ".lock"

# What the index is allowed to cost to read.
#
# The document is this program's own -- one record per cached build step, a few
# kilobytes -- but the file standing under its name is not: on Termux the cache
# is nested inside the $PREFIX that is bound read-write into every non-isolated
# container. A read that stops only at end of file lets whoever is in that
# position decide how many bytes every `build` pulls into memory before finding
# out the document is nonsense, and it need not even be nonsense -- a valid
# index padded with whitespace parses, and is then resident. 16 MiB is orders of
# magnitude above anything written here.
_MAX_INDEX_BYTES = 16 * 1024 * 1024

_READ_CHUNK = 1 << 20


def _index_walk() -> tuple[str, tuple[str, ...]]:
    """Return (trust root, components below it) for the index's directory.

    The cache is a state directory of this program's own, but on Termux it is
    nested inside RUNTIME_DIR while elsewhere it is a root of its own, so how
    much of the path may be walked is not fixed. Taking RUNTIME_DIR as the root
    whenever the index sits below it keeps `cache` itself inside the O_NOFOLLOW
    walk there, and leaves the walk trivial where it is not.
    """
    parent = os.path.dirname(_INDEX_PATH)
    prefix = RUNTIME_DIR.rstrip(os.sep) + os.sep
    if parent.startswith(prefix):
        return RUNTIME_DIR, tuple(part for part in parent[len(prefix) :].split(os.sep) if part)
    return parent, ()


def _index_dir_fd(*, create: bool = False) -> int:
    """Open the directory holding the index. Descriptor, or raises.

    The root is created by name when asked, since a first build on a machine
    that has never cached one must not fail merely because the cache directory
    does not exist yet. Everything below it is opened off the level above with
    O_NOFOLLOW, so a component replaced by a symlink raises instead of sending
    the index -- or the lock taken over it -- somewhere else. On Termux the
    cache sits under the $PREFIX that is bound read-write into every
    non-isolated container, which is what puts a guest in a position to try.
    """
    root, parts = _index_walk()
    if create:
        with contextlib.suppress(OSError):
            os.makedirs(root, exist_ok=True)
    root_fd = dirfd.opendir(root)
    try:
        return dirfd.descend_at(root_fd, parts, create=create)
    finally:
        os.close(root_fd)


@contextlib.contextmanager
def _index_lock() -> typing.Iterator[None]:
    """Hold an exclusive flock on the index for the read-modify-write cycle.

    The index is a single JSON file shared across all builds, so two
    concurrent `record()` calls would otherwise read-modify-write
    independently and the last writer would silently drop the other's
    entry. The flock serialises updates; on filesystems that don't
    support flock the call proceeds unlocked (last-writer-wins, same
    behaviour as before).

    The lock file is named to `locking`, which opens it under the descriptor
    and replaces anything standing there that is not a plain file. A name it
    cannot clear -- like a directory it cannot reach -- ends in the unlocked
    path rather than a refusal: the worst an unserialised `record()` costs is
    the other build's entry, and the file it publishes is written through
    `atomic_write` either way.
    """
    try:
        dir_fd = _index_dir_fd(create=True)
    except OSError:
        yield
        return
    try:
        fd = locking.open_lock_file_at(dir_fd, os.path.basename(_INDEX_LOCK_PATH), _INDEX_LOCK_PATH)
    finally:
        os.close(dir_fd)
    if fd is None:
        yield
        return
    try:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_index() -> bytes:
    """Return the index's bytes, read through the walked descriptor.

    Raises what the open raises. FileNotFoundError means what it says -- no
    index yet -- and stays apart from every other failure, which is an entry
    that is there and is not an index: a symlink O_NOFOLLOW refused, a FIFO, a
    directory. `_load_index` answers both with an empty index, but the read has
    no business being the thing that decides that.

    An index too large to read is that same kind of entry, and is refused the
    same way rather than truncated: a prefix of a JSON document parses as no
    index at all, so `record()` would write over entries it had merely declined
    to finish reading. Whatever stands there holding more than
    `_MAX_INDEX_BYTES` is not an index this program wrote.
    """
    dir_fd = _index_dir_fd()
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, os.path.basename(_INDEX_PATH), os.O_RDONLY)
    finally:
        os.close(dir_fd)
    try:
        return _read_capped(fd)
    finally:
        os.close(fd)


def _read_capped(fd: int) -> bytes:
    """Everything behind *fd*, or OSError(EFBIG) past `_MAX_INDEX_BYTES`.

    The cap counts the bytes actually drawn rather than an fstat's st_size: the
    size a file reports is not a promise about what reading it costs, and one
    being appended to while it is read would pass a size check and then exceed
    it. The descriptor stays the caller's to close.
    """
    chunks: list[bytes] = []
    remaining = _MAX_INDEX_BYTES + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, _READ_CHUNK))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining <= 0:
        raise OSError(errno.EFBIG, f"build cache index is larger than {_MAX_INDEX_BYTES} bytes")
    return b"".join(chunks)


def _load_index() -> dict[str, typing.Any]:
    try:
        data = json.loads(_read_index())
    except (OSError, ValueError):
        return {"version": 1, "entries": {}}
    if not isinstance(data, dict):
        return {"version": 1, "entries": {}}
    data.setdefault("version", 1)
    data.setdefault("entries", {})
    if not isinstance(data["entries"], dict):
        data["entries"] = {}
    return data


def _save_index(data: dict[str, typing.Any]) -> None:
    with atomic_write(_INDEX_PATH) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def lookup(recipe_hash: str | None) -> dict[str, typing.Any] | None:
    """Return the cache entry dict for `recipe_hash`, or None."""
    if not recipe_hash:
        return None
    data = _load_index()
    res = data.get("entries", {}).get(recipe_hash)
    if isinstance(res, dict):
        return res
    return None


def index_path() -> str:
    """Return the on-disk location of the build-cache index."""
    return _INDEX_PATH


def discard_index() -> tuple[bool, int]:
    """Delete the index, returning (removed, the bytes it occupied).

    *removed* is False when there was nothing there to delete; a stat that
    fails leaves the size at zero and lets the unlink decide the outcome. An
    OSError is deliberately left to propagate: a caller dropping the index in
    order to collect the layers it pinned must not go on to delete them while
    the entries naming them are still on disk.

    No lock is taken. `record()` serialises the read-modify-write cycle it
    performs, but an unlink is not one -- a concurrent `record()` either wrote
    before it and loses its entry, which is the point of the call, or writes
    afterwards and starts a fresh index. Neither outcome is a torn file, the
    same reason `lookup()` reads unlocked. The `.lock` file is left where it
    is: it is empty and `_index_lock()` recreates it on demand.

    The entry is stat'd and unlinked under the walked descriptor, and without
    following a final symlink, so what goes is whatever is standing in the
    index's place -- which is the outcome the caller wants either way, since a
    planted entry pins nothing.
    """
    name = os.path.basename(_INDEX_PATH)
    try:
        dir_fd = _index_dir_fd()
    except FileNotFoundError:
        return False, 0
    try:
        try:
            size = dirfd.lstat_at(dir_fd, name).st_size
        except FileNotFoundError:
            return False, 0
        except OSError:
            size = 0
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return False, 0
    finally:
        os.close(dir_fd)
    return True, size


def record(
    recipe_hash: str,
    layer_digest: str,
    diff_id: str,
    size: int,
    image_config_patch: dict[str, typing.Any] | None = None,
) -> None:
    """Record a build-cache entry."""
    # Lock around the full read-modify-write so concurrent builds don't
    # clobber each other's records.
    with _index_lock():
        data = _load_index()
        entries = data.setdefault("entries", {})
        entries[recipe_hash] = {
            "layer_digest": layer_digest,
            "diff_id": diff_id,
            "size": size,
            "image_config_patch": image_config_patch or {},
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        _save_index(data)


# ---------------------------------------------------------------------------
# Recipe-hash construction
# ---------------------------------------------------------------------------


def _canonical_value(value: typing.Any) -> str:
    if isinstance(value, list):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _canonical_flags(flags: dict[str, typing.Any] | None) -> str:
    if not flags:
        return ""
    # List values (repeated flags, e.g. RUN --mount) serialise as JSON so
    # the hash is deterministic and distinct from a same-text string value.
    return "&".join(f"{k}={_canonical_value(v)}" for k, v in sorted(flags.items()))


def compute_recipe_hash(
    parent_layer_digest: str | None,
    instr: dict[str, typing.Any],
    extra_inputs: str | bytes = "",
) -> str:
    """Compute the recipe hash for `instr` chained onto `parent_layer_digest`.

    `extra_inputs` is an opaque string that the caller appends to
    capture inputs the instruction itself doesn't carry (e.g. the
    digests of files referenced by COPY/ADD, or the relevant
    env+ARG state visible to a RUN).
    """
    h = hashlib.sha256()
    h.update((parent_layer_digest or "").encode())
    h.update(b"\x00")
    h.update(instr["name"].encode())
    h.update(b"\x00")
    h.update(_canonical_flags(instr.get("flags", {})).encode())
    h.update(b"\x00")
    h.update(_canonical_value(instr.get("value", "")).encode())
    h.update(b"\x00")
    for hd in instr.get("heredocs", []) or []:
        h.update(b"<<")
        h.update((hd.get("body") or "").encode())
        h.update(b">>")
    h.update(b"\x00")
    if isinstance(extra_inputs, bytes):
        h.update(extra_inputs)
    else:
        h.update(str(extra_inputs).encode())
    return h.hexdigest()
