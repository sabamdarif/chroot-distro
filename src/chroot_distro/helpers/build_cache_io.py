# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""A portable copy of the build-step cache: write one directory, read one back.

`export_cache` puts what a build's RUN steps produced into a directory the user
named, and `import_cache` reads such a directory back into this machine's cache.
The layout is this program's own:

    <dir>/build-cache.json    {"version": 1, "entries": {...}}, the index's shape
    <dir>/blobs/<digest>      one layer blob, under the layer cache's own filename

`build-cache.json` rather than `index.json` because an OCI image layout claims
that name, and a `--cache-to` aimed at a directory holding one must not overwrite
it. The records are `build_cache`'s own verbatim, so neither direction translates
anything. BuildKit's cache format was never a candidate: it addresses solver
vertices this program has none of, so nothing on either side could read it.

An export carries the steps that build dispatched and no others. The whole index
would be less code, and would put the layers of a build with nothing to do with
this one into an artifact the user is about to publish. It merges into whatever
the directory already holds, so a shared directory accumulates across builds and
nothing evicts, which is the growth the local index has too.

Import is the trust boundary. The directory is the user's to name, but its
contents are nobody's to vouch for, so a blob is read once and hashed twice,
against the digest that names it and the diff_id its entry claims, before it is
published into the layer cache. That is what keeps the invariant `layers.py`
states: the file at `layer_cache_path(digest)` is either the verified bytes for
that digest or absent. An entry that fails is skipped and its step rebuilds, so a
corrupt directory costs time rather than a build.

What no check here can answer is whether a recipe hash truly names the layer its
entry points at: a directory offering another build's layer for this build's step
would be believed. `--cache-from` trusts the directory the way buildx does, and
hashing bounds that trust to content the directory actually holds.
"""

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import typing
import zlib

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_replace, atomic_write
from chroot_distro.constants import LAYER_CACHE_DIR
from chroot_distro.helpers import build_cache
from chroot_distro.helpers.docker import layer_cache_path

INDEX_NAME = "build-cache.json"
BLOBS_NAME = "blobs"

_SCHEMA_VERSION = 1
_READ_CHUNK = 1 << 20

# What `build_cache.compute_recipe_hash` produces. A recipe hash is a dictionary
# key and never a path, so this refuses nothing dangerous; it keeps the index
# this program merges into to records it could have written itself.
_RECIPE_RE = re.compile(r"^[0-9a-f]{64}$")


class _RefusedError(Exception):
    """Raised inside a publishing block so the temporary goes and nothing lands."""


def export_cache(dest: str, recipes: typing.Iterable[str]) -> tuple[int, int]:
    """Write the cache entries for *recipes* into *dest*. Returns (steps, bytes).

    An entry whose blob has left the layer cache is dropped rather than exported:
    a record pointing at bytes the directory does not carry is a refusal on the
    next import and a rebuild either way.

    The index and the blobs are written 0644 and the directories 0755, because
    the build that writes them is root and whoever archives the directory
    afterwards usually is not.
    """
    existing = _read_dir_index(dest)
    blobs_dir = os.path.join(dest, BLOBS_NAME)
    os.makedirs(blobs_dir, 0o755, exist_ok=True)

    exported: dict[str, dict[str, typing.Any]] = {}
    total = 0
    for recipe, entry in sorted(build_cache.entries_for(recipes).items()):
        name = os.path.basename(layer_cache_path(entry["layer_digest"]))
        src = os.path.join(LAYER_CACHE_DIR, name)
        try:
            st = os.lstat(src)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if not _blob_already_there(blobs_dir, name, st.st_size):
            with open(src, "rb") as fh, atomic_write(os.path.join(blobs_dir, name), binary_mode=True, mode=0o644) as out:
                shutil.copyfileobj(fh, out, _READ_CHUNK)
        exported[recipe] = entry
        total += st.st_size

    with atomic_write(os.path.join(dest, INDEX_NAME), mode=0o644) as fh:
        json.dump({"version": _SCHEMA_VERSION, "entries": {**existing, **exported}}, fh, indent=2, sort_keys=True)
    return len(exported), total


def _blob_already_there(blobs_dir: str, name: str, size: int) -> bool:
    """True when a plain file of the right size already stands under *name*.

    The name is the digest of the content, so the size is as much as a re-copy
    would establish without hashing back what it wrote. Anything else standing
    there, a symlink or a directory included, is replaced by the copy.
    """
    try:
        st = os.lstat(os.path.join(blobs_dir, name))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_size == size


def import_cache(src: str) -> tuple[int, int]:
    """Merge the cache directory at *src* into this machine's build cache.

    Returns (steps added, entries refused). A directory that is not there, or one
    holding no index, adds nothing and refuses nothing: the first build in a fresh
    checkout is the case a shared cache directory exists for, not an error. A
    `ValueError` is a directory that is there and is not one.
    """
    entries = _read_dir_index(src)
    if not entries:
        return 0, 0

    blobs_fd = _open_blobs(src)
    if blobs_fd is None:
        return 0, len(entries)

    accepted: dict[str, dict[str, typing.Any]] = {}
    refused = 0
    try:
        for recipe, entry in sorted(entries.items()):
            if _take_entry(blobs_fd, recipe, entry):
                accepted[recipe] = entry
            else:
                refused += 1
    finally:
        os.close(blobs_fd)
    return build_cache.merge_entries(accepted), refused


def _open_blobs(src: str) -> int | None:
    """A descriptor on *src*'s blob directory, or None when there is not one."""
    try:
        root_fd = dirfd.opendir(src)
    except OSError:
        return None
    try:
        return dirfd.opendir_at(root_fd, BLOBS_NAME)
    except OSError:
        return None
    finally:
        os.close(root_fd)


def _take_entry(blobs_fd: int, recipe: str, entry: typing.Any) -> bool:
    """Verify one entry's blob into the layer cache. True when the entry is usable.

    Every field is checked before a byte is read, because every one of them is
    read back out: the digest becomes a filename, and the size and the diff_id go
    into the manifest a later build publishes. sha256 alone, which is what the
    only other writer of this cache (`docker/layers.download_blob`) accepts, since
    an algorithm nothing here can compute cannot be verified.
    """
    if not _RECIPE_RE.match(recipe) or not isinstance(entry, dict) or not build_cache.entry_is_usable(entry):
        return False
    digest = entry["layer_digest"]
    algo, _, expected_hex = digest.partition(":")
    if algo.lower() != "sha256":
        return False
    dest = layer_cache_path(digest)
    if os.path.isfile(dest):
        # Already the verified bytes for that digest, or absent: the layer
        # cache's own invariant leaves nothing here to check or to copy.
        return True
    try:
        fd, st = dirfd.open_regular_at(blobs_fd, os.path.basename(dest), os.O_RDONLY)
    except OSError:
        return False
    try:
        if st.st_size != entry["size"]:
            return False
        return _publish_verified(fd, dest, expected_hex, entry["diff_id"])
    finally:
        os.close(fd)


def _publish_verified(fd: int, dest: str, expected_hex: str, diff_id: str) -> bool:
    """Copy the blob behind *fd* into *dest*, or publish nothing at all.

    One pass and two hashes: the bytes as they stand against the digest that names
    the file, and their gunzipped form against the diff_id the entry claims a
    manifest will carry. Both are compared inside the `atomic_replace` block, the
    way `download_blob` compares its own, so a mismatch removes the temporary
    instead of renaming it over a name the rest of the program then trusts.
    """
    compressed = hashlib.sha256()
    plain = hashlib.sha256()
    inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        with atomic_replace(dest, mode=0o644) as tmp, open(tmp, "wb") as out:
            while chunk := os.read(fd, _READ_CHUNK):
                compressed.update(chunk)
                plain.update(inflate.decompress(chunk))
                out.write(chunk)
            plain.update(inflate.flush())
            out.flush()
            os.fsync(out.fileno())
            if compressed.hexdigest() != expected_hex.lower() or f"sha256:{plain.hexdigest()}" != diff_id.lower():
                raise _RefusedError
    except (OSError, zlib.error, _RefusedError):
        return False
    return True


def _read_dir_index(path: str) -> dict[str, typing.Any]:
    """The entries the cache directory at *path* holds; {} when it holds none.

    Anything standing under `build-cache.json` that is not one raises, in both
    directions: on the way in the user asked for it by name, and on the way out an
    export merges into it, so a document this cannot read is one it must not write
    over either. A schema version it does not know is that same refusal.

    The read is capped through the function `build_cache` caps its own index with,
    and for the reason that module gives: `json.loads` stops at end of file, so
    without a ceiling whoever wrote the directory decides how many bytes a build
    holds in memory before finding out the document is nonsense.
    """
    name = os.path.join(path, INDEX_NAME)
    try:
        dir_fd = dirfd.opendir(path)
    except OSError:
        return {}
    try:
        fd, _st = dirfd.open_regular_at(dir_fd, INDEX_NAME, os.O_RDONLY)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ValueError(f"'{name}' is not a readable file ({exc.strerror or exc})") from exc
    finally:
        os.close(dir_fd)
    try:
        data = json.loads(build_cache._read_capped(fd))
    except (OSError, ValueError) as exc:
        raise ValueError(f"'{name}' is not a build cache index ({exc})") from exc
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)

    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        raise ValueError(f"'{name}' is not a build cache index")
    if data.get("version") != _SCHEMA_VERSION:
        raise ValueError(f"'{name}' records schema version {data.get('version')!r}, not {_SCHEMA_VERSION}")
    entries: dict[str, typing.Any] = data["entries"]
    return entries
