# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""COPY and ADD: locate the sources, write them into the rootfs, pack the layer.

One instruction builds one `file_map`, an arcname to entry mapping describing
what the rootfs should hold, and that map is both materialised on disk
(`_materialise_files`) and packed into the layer (`layer_diff.write_files_layer`),
so the tree and the image record cannot drift apart.

No file_map entry ever holds content in memory. One file_map covers a whole
instruction, so a URL response body, or every regular member of an
auto-extracted archive, would all be live at once and one instruction could take
the build process out. Content that does not already exist as a file is spooled
into a directory off engine.tmp_root and referenced by (that directory's
descriptor, name), which is where it was headed anyway, and tmp_root is removed
when the build ends.

Three source kinds, decided per operand: a URL (ADD only), the build context, and
another rootfs (`--from`: an earlier stage, or an image pulled into a throwaway
tree). None of the three is a tree this build wrote, so `_SourceTree` is the only
way one is located. It resolves a spec to components with each hop clamped inside
the tree, then hands back descriptors walked down O_NOFOLLOW rather than the path
it resolved. The last component is left unresolved deliberately, because COPY
copies a symlink as a symlink instead of reading through it.

The write side re-walks for the same reason, and also leaves its last component
alone, so every kind drops a link standing at the name before writing: an ADD'd
tar shipping `etc -> <host dir>` and then an `etc/passwd` member is the case that
buys.

Flags are an allow-list. `--link` is refused as BuildKit-only and `--checksum`
and `--keep-git-dir` as unimplemented, never ignored, since each one changes what
the instruction is meant to produce.
"""

import contextlib
import hashlib
import http.client
import os
import re
import shutil
import stat
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import time
import typing
import urllib.error
import urllib.parse
import urllib.request

from chroot_distro import dirfd
from chroot_distro.atomic import publish_file
from chroot_distro.helpers.build_engine.dockerignore import (
    is_ignored,
    simple_glob,
)
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.parsing import (
    TAR_HEADER_BYTES,
    is_tar_header,
    looks_like_url,
    split_operands,
)
from chroot_distro.helpers.build_engine.users import resolve_chown
from chroot_distro.helpers.docker import (
    AuthStrippingRedirectHandler,
    layer_cache_path,
    pull_image,
)
from chroot_distro.helpers.layer_diff import MapSources, write_files_layer
from chroot_distro.helpers.tar_extract import safe_resolve_parts
from chroot_distro.message import log_info

_SPOOL_CHUNK = 1 << 17


class _SourceTree:
    """The tree one COPY/ADD reads its sources out of.

    The build context, another stage's rootfs, or an image pulled for
    COPY --from: trees this program did not write, whose symlinks are therefore
    whoever wrote them's choice.

    `resolve()` answers where a source spec lands with tar_extract's clamped
    walk: existing symlink components are followed, but an absolute target
    re-anchors at the root and `..` can never climb out of it. That is both the
    confinement and the meaning a path has inside an image, where the guest's
    `/` *is* the rootfs, so an absolute link an image legitimately ships
    (`/usr/bin/python -> /usr/local/bin/python`) still resolves to the right
    file. The final component is deliberately left unresolved: COPY copies a
    symlink as a symlink rather than reading through it.

    Nothing here hands a path back to open. Resolving decides each component by
    name, so a component swapped afterwards would be followed by whatever acted
    on the answer; every descriptor this class returns is walked down from the
    root with O_NOFOLLOW instead, and the entries recorded in a file_map carry
    (root, components) so the reads that come later can do the same.

    *root_fd* is the tree when the caller has pinned it (a build stage's
    rootfs, which is a name inside the build's scratch tree and so re-pointable
    by anything running as the invoking user). The walk then starts from that
    inode and the entries carry it, so neither the enumeration nor the read
    resolves the tree's own name a second time.
    """

    def __init__(self, root: str, *, root_fd: int | None = None) -> None:
        self.root = os.path.abspath(root)
        self.root_fd = root_fd

    def resolve(self, parts: typing.Sequence[str]) -> list[str] | None:
        """Where *parts* lands beneath the root, as components, or None.

        None means a symlink loop or chain long enough to look like one.
        """
        clean = [p for p in parts if p not in ("", os.curdir)]
        if not clean:
            return []
        resolved = safe_resolve_parts(self.root, clean[:-1], root_fd=self.root_fd)
        if resolved is None:
            return None
        return [*resolved, clean[-1]]

    def opendir(self, parts: typing.Sequence[str]) -> int:
        """A descriptor on the directory *parts* names. Raises OSError."""
        if self.root_fd is not None:
            return dirfd.descend_at(self.root_fd, parts)
        root_fd = dirfd.opendir(self.root)
        try:
            return dirfd.descend_at(root_fd, parts)
        finally:
            os.close(root_fd)

    def lstat(self, parts: typing.Sequence[str]) -> os.stat_result | None:
        """What *parts* names, without following it. stat, or None."""
        if not parts:
            if self.root_fd is not None:
                return os.fstat(self.root_fd)
            try:
                return os.stat(self.root)
            except OSError:
                return None
        try:
            fd = self.opendir(parts[:-1])
        except OSError:
            return None
        try:
            return dirfd.lstat_at(fd, parts[-1])
        except OSError:
            return None
        finally:
            os.close(fd)

    def open_file(self, parts: typing.Sequence[str]) -> tuple[int, os.stat_result]:
        """Open *parts* as a regular file. (fd, stat); raises OSError."""
        fd = self.opendir(parts[:-1])
        try:
            return dirfd.open_regular_at(fd, parts[-1], os.O_RDONLY)
        finally:
            os.close(fd)


def _spec_parts(src: str) -> list[str] | None:
    """The components of a COPY/ADD source spec, or None for a `..` in it.

    A leading '/' is dropped: Docker reads both spellings as relative to the
    source tree's own root. A `..` written in the spec is refused rather than
    clamped, the same rule the [name:]path resolver applies to a container
    path, and the same answer Docker gives for a source outside the build
    context.
    """
    parts = [p for p in src.lstrip("/").split("/") if p not in ("", os.curdir)]
    if os.pardir in parts:
        return None
    return parts


def _rel_name(parts: typing.Sequence[str]) -> str:
    """The '/'-joined form of *parts*, as .dockerignore matches names."""
    return "/".join(parts) if parts else os.curdir


def _open_scratch_dir(engine: typing.Any, name: str) -> tuple[str, int]:
    """Create *name* directly under the build's scratch root; (path, fd).

    Made and opened off the scratch root's own descriptor when the build has
    one, so the directory is inside the tree the run created rather than
    wherever the name resolves to now: `tmp_root` is a name anything running as
    the invoking user can re-point, a process a previous RUN step left behind
    included.
    """
    path = os.path.join(engine.tmp_root, name)
    root_fd = getattr(engine, "tmp_root_fd", None)
    try:
        if root_fd is None:
            os.makedirs(path, exist_ok=True)
            fd = dirfd.opendir(path)
        else:
            fd = dirfd.descend_at(root_fd, (name,), create=True)
    except OSError as exc:
        raise BuildError(f"cannot create the build scratch directory {name}: {exc}") from exc
    return path, fd


class _Spool:
    """The directory ADD stages content it did not find as a file in.

    A URL's body and each regular member of an auto-extracted archive are
    written here and then read twice more, once to materialise them into the
    rootfs and once to pack them into the layer. Both of those reads go through
    the descriptor this holds, so the only name lookup is the create.
    """

    __slots__ = ("_seq", "fd", "path")

    def __init__(self, path: str, fd: int) -> None:
        self.path = path
        self.fd = fd
        self._seq = 0

    def stream(self, fobj: typing.IO[bytes]) -> tuple[str, int]:
        """Copy *fobj* into a fresh file under the spool; return (name, bytes).

        O_EXCL on a name carrying random bytes, rather than a temporary the
        caller could predict: what lands here is materialised into the rootfs
        and packed into the layer `push` uploads, so a symlink planted under the
        name would have decided where the bytes went and what was read back.

        The count comes back because one caller has something to compare it
        against: a URL response that declared a Content-Length.
        """
        while True:
            self._seq += 1
            name = f"add-{self._seq}.{os.urandom(4).hex()}"
            try:
                fd, _st = dirfd.open_new_at(self.fd, name, 0o600)
            except FileExistsError:
                continue
            break
        try:
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(fobj, out, _SPOOL_CHUNK)
                written = out.tell()
        except BaseException:
            dirfd.unlink_quietly(self.fd, name)
            raise
        return name, written

    def close(self) -> None:
        """Release the spool descriptor. Idempotent."""
        fd, self.fd = self.fd, -1
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)


def _file_entry(
    file_map: dict[str, typing.Any],
    arcname: str,
    root: str,
    parts: typing.Sequence[str],
    mode: int,
    uid: int,
    gid: int,
    mtime: int,
    size: int,
    root_fd: int | None = None,
) -> None:
    """Record a regular file in *file_map* as (root, components).

    `src` is the joined form, for a message that has to name the source; nothing
    reads through it. The bytes come from a walk of `rel` down from `root`
    (layer_diff.MapSources), and `size` is what the enumeration measured, which
    is all the progress bar's denominator needs; the pack sizes each file off
    the descriptor it reads.

    `root_fd` is the descriptor that walk starts from when the caller has one,
    which is what keeps the read anchored to the tree the entry was enumerated
    in; `root` alone is resolved again at pack time.
    """
    file_map[arcname] = {
        "kind": "file",
        "root": root,
        "root_fd": root_fd,
        "rel": tuple(parts),
        "src": os.path.join(root, *parts),
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
        "size": size,
    }


def _spool_entry(
    file_map: dict[str, typing.Any],
    arcname: str,
    spool: _Spool,
    name: str,
    mode: int,
    uid: int,
    gid: int,
    mtime: int,
) -> None:
    """Record *name* under *spool* in *file_map* as an ordinary file entry.

    The timestamp goes on the spool file itself because that is where both
    consumers read it from: layer_diff's "file" kind takes an entry's mode,
    uid and gid from the dict but its mtime from the file on disk. The value
    came out of an archive header or off the clock, so it can be any number
    at all: os.utime() raises OverflowError, not OSError, on one the
    platform cannot store.

    The stamp and the size go through the spool descriptor, and the entry
    carries it, so the file the layer ends up holding is the one stream()
    created and not another that answers to the name by then.
    """
    with contextlib.suppress(OSError, OverflowError, ValueError):
        os.utime(name, (mtime, mtime), dir_fd=spool.fd, follow_symlinks=False)
    try:
        size = dirfd.lstat_at(spool.fd, name).st_size
    except OSError:
        size = 0
    _file_entry(file_map, arcname, spool.path, [name], mode, uid, gid, mtime, size, root_fd=spool.fd)


def do_copy(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """COPY [--from=X] [--chown] [--chmod] SRC DEST: pack files into a layer."""
    _do_copy_or_add(engine, instr, allow_url=False, auto_extract=False)


def do_add(engine: typing.Any, instr: dict[str, typing.Any]) -> None:
    """ADD: like COPY but accepts URL sources and auto-extracts tarballs."""
    _do_copy_or_add(engine, instr, allow_url=True, auto_extract=True)


def _do_copy_or_add(
    engine: typing.Any,
    instr: dict[str, typing.Any],
    allow_url: bool,
    auto_extract: bool,
) -> None:
    stage = engine.current
    flags = instr.get("flags") or {}

    tokens = list(instr["value"]) if instr["exec_form"] else split_operands(instr["value"], instr)
    if len(tokens) < 2:
        raise BuildError(f"{instr['name']} requires at least one source and a destination at line {instr['lineno']}.")

    sources = tokens[:-1]
    dest = tokens[-1]

    allowed = {"chown", "chmod", "from"}
    if instr["name"] == "COPY":
        allowed.add("parents")
    for k in flags:
        if k == "link":
            raise BuildError(
                f"{instr['name']} --link is a BuildKit-only flag and is not supported (line {instr['lineno']})."
            )
        if k in ("checksum", "keep-git-dir"):
            raise BuildError(f"{instr['name']} --{k} is not supported yet (line {instr['lineno']}).")
        if k not in allowed:
            raise BuildError(
                f"{instr['name']} --{k} is not supported (line {instr['lineno']}); refusing to silently ignore it."
            )
    parents = "parents" in flags

    chown = flags.get("chown")
    chmod = flags.get("chmod")
    from_stage = flags.get("from")
    from_rootfs = None
    from_rootfs_fd = None
    # The throwaway rootfs is ours to close; another stage's descriptor is not.
    owned_fd = None
    if from_stage:
        ref_stage = engine.stages.get(from_stage)
        if ref_stage is None:
            from_rootfs, owned_fd = _pull_throwaway_image(engine, from_stage)
            from_rootfs_fd = owned_fd
        else:
            from_rootfs = ref_stage.rootfs_dir
            from_rootfs_fd = ref_stage.rootfs_fd

    resolved = []
    if from_rootfs is None:
        for src in sources:
            if allow_url and looks_like_url(src):
                resolved.append(("url", src))
            else:
                resolved.append(("ctx", src))
    else:
        for src in sources:
            resolved.append(("rootfs", src))

    is_dir_dest = dest.endswith("/") or len(sources) > 1
    if not dest.startswith("/"):
        dest = os.path.normpath(os.path.join(stage.workdir or "/", dest))

    uid, gid = resolve_chown(stage.rootfs_dir, chown, root_fd=stage.rootfs_fd) if chown else (0, 0)
    mode_override = int(chmod, 8) if chmod and re.match(r"^[0-7]+$", chmod) else None

    file_map: dict[str, typing.Any] = {}
    spool = _Spool(*_open_scratch_dir(engine, "add-spool")) if allow_url or auto_extract else None
    try:
        for kind, src in resolved:
            if kind == "url":
                assert spool is not None
                _copy_url(src, dest, file_map, uid, gid, mode_override, spool)
            elif kind == "ctx":
                _copy_from_context(
                    engine,
                    src,
                    dest,
                    is_dir_dest,
                    file_map,
                    uid,
                    gid,
                    mode_override,
                    auto_extract,
                    parents=parents,
                    spool=spool,
                )
            elif kind == "rootfs":
                assert from_rootfs is not None
                _copy_from_rootfs(
                    from_rootfs,
                    src,
                    dest,
                    is_dir_dest,
                    file_map,
                    uid,
                    gid,
                    mode_override,
                    parents=parents,
                    from_rootfs_fd=from_rootfs_fd,
                )

        if not file_map:
            return

        _materialise_files(stage.rootfs_dir, file_map, rootfs_fd=stage.rootfs_fd)

        tmp_layer_path = os.path.join(
            engine.tmp_root,
            f"layer-{stage.index}-{len(stage.layers)}.tar.gz",
        )
        # Still inside the try: the pack reads the spooled files and the source
        # tree back through the descriptors closed below.
        digest, size, diff_id = write_files_layer(file_map, tmp_layer_path)
        # See run_step: the layer cache is walked down to, not named.
        publish_file(tmp_layer_path, layer_cache_path(digest))
        stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
        stage.parent_layer_digest = digest
    finally:
        if spool is not None:
            spool.close()
        if owned_fd is not None:
            with contextlib.suppress(OSError):
                os.close(owned_fd)


def _pull_throwaway_image(engine: typing.Any, image_ref: str) -> tuple[str, int]:
    """Pull an external image into a scratch rootfs for COPY --from; (path, fd).

    The descriptor is the caller's to close. The name is resolved once, when the
    directory is created off the scratch root, and the emptiness check, the pull
    and every read the instruction then makes go through the descriptor: an
    image this build has no say over is what lands in there.

    The platform is the build's target and not the platform of the stage doing
    the copying, which is how Docker resolves an external `--from` too: a stage
    running on the build platform to assemble a target rootfs has to receive the
    target's files, and a stage that wants native ones names a FROM of its own.
    """
    slot = hashlib.sha256(image_ref.encode()).hexdigest()[:16]
    rootfs, rootfs_fd = _open_scratch_dir(engine, "copyfrom-" + slot)
    try:
        if dirfd.listdir_at(rootfs_fd):
            return rootfs, rootfs_fd
        if not engine.quiet:
            log_info(f"COPY --from='{image_ref}': fetching external image...")
        try:
            pull_image(image_ref, rootfs_fd, engine.target_platform)
        except (OSError, RuntimeError) as exc:
            raise BuildError(f"COPY --from={image_ref}: {exc}") from exc
    except BaseException:
        os.close(rootfs_fd)
        raise
    return rootfs, rootfs_fd


def _split_parents_pivot(pattern: str) -> tuple[str, str]:
    """Split a COPY --parents source on its ``/./`` pivot.

    Returns (pattern_without_pivot, anchor). The anchor is the normalised
    path before the first ``/./``; paths are preserved relative to it.
    Without a pivot the anchor is '' (preserve relative to the root).
    """
    if "/./" not in pattern:
        return pattern, ""
    anchor, _, rest = pattern.partition("/./")
    clean = os.path.normpath(anchor)
    if clean in (".", ""):
        clean = ""
    return (f"{anchor}/{rest}" if anchor else rest), clean


def _parents_dest(dest: str, rel: str, anchor: str) -> str:
    """Destination for one --parents source: dest / (rel relative to anchor)."""
    preserved = os.path.relpath(rel, anchor) if anchor else rel
    if preserved.startswith(".."):
        raise BuildError(f"COPY --parents source '{rel}' is outside its /./ pivot '{anchor}'.")
    return dest.rstrip("/") + "/" + preserved


def _copy_from_context(
    engine: typing.Any,
    src: str,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    auto_extract: bool,
    parents: bool = False,
    spool: _Spool | None = None,
) -> None:
    """COPY/ADD from the build context, confined to it.

    A source that resolves outside the context does not exist as far as this is
    concerned: `..` in the spec is refused outright, and a symlink leading out of
    the context re-anchors at its root, so what was `escape/secret` with
    `escape -> /` becomes plain `secret` and is reported missing if the context
    holds no such file. That is what the daemon makes of a context symlink too:
    it only ever sees the unpacked context, never the host tree the link named.
    """
    tree = _SourceTree(engine.build_dir)
    spec, anchor = _split_parents_pivot(src.lstrip("/")) if parents else (src, "")
    raw = _spec_parts(spec)
    if raw is None:
        raise BuildError(f"COPY source '{src}' escapes the build context.")
    parts = tree.resolve(raw)
    st = tree.lstat(parts) if parts is not None else None
    if parts is None or st is None:
        # A wildcard, or a name that is not there. glob() answers on the spelling
        # of a path the same way the old containment check did, so every match is
        # put through the walk as well and one that only exists outside the
        # context counts for nothing: with no match left the source is not in the
        # context, which is what the user is told rather than the instruction
        # quietly copying nothing.
        matches = sorted(simple_glob(engine.build_dir, _rel_name(raw)))
        matches = [m for m in matches if not is_ignored(m, list(engine.ignore_patterns))]
        found = []
        for m in matches:
            m_raw = _spec_parts(m)
            m_parts = tree.resolve(m_raw) if m_raw is not None else None
            m_st = tree.lstat(m_parts) if m_parts is not None else None
            if m_parts is not None and m_st is not None:
                found.append((m, m_parts, m_st))
        if not found:
            raise BuildError(f"COPY/ADD source '{src}' not found in build context.")
        for m, m_parts, m_st in found:
            _add_to_file_map(
                tree,
                m_parts,
                m_st,
                _parents_dest(dest, m, anchor) if parents else dest,
                is_dir_dest=not parents,
                file_map=file_map,
                uid=uid,
                gid=gid,
                mode_override=mode_override,
                auto_extract=auto_extract,
                src_rel=_rel_name(m_parts),
                ignore_patterns=engine.ignore_patterns,
                spool=spool,
            )
        return
    if is_ignored(_rel_name(parts), list(engine.ignore_patterns)):
        return
    if parents:
        # Preserved relative to the spelling rather than to where the walk
        # landed: --parents reproduces the path the Dockerfile wrote under dest,
        # and a symlinked component resolves to a name that is not below the
        # pivot at all.
        dest = _parents_dest(dest, _rel_name(raw), anchor)
        is_dir_dest = False
    _add_to_file_map(
        tree,
        parts,
        st,
        dest,
        is_dir_dest=is_dir_dest,
        file_map=file_map,
        uid=uid,
        gid=gid,
        mode_override=mode_override,
        auto_extract=auto_extract,
        src_rel=_rel_name(parts),
        ignore_patterns=engine.ignore_patterns,
        spool=spool,
    )


def _copy_from_rootfs(
    from_rootfs: str,
    src: str,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    parents: bool = False,
    from_rootfs_fd: int | None = None,
) -> None:
    """COPY --from a stage or image rootfs, confined to that rootfs.

    The source tree here is image content outright, so the walk matters twice
    over: `/escape/file` with `escape -> /some/host/path` shipped in the image
    used to read the host's file and pack it into the layer, without the
    Dockerfile or the build context saying anything unusual. Clamped, the link
    means inside the image the way it does to the guest.

    *from_rootfs_fd* pins that rootfs when the caller has a descriptor on it --
    an earlier stage's, or the one the throwaway image was pulled into. Both are
    names inside the build's scratch tree.
    """
    tree = _SourceTree(from_rootfs, root_fd=from_rootfs_fd)
    spec, anchor = _split_parents_pivot(src.lstrip("/")) if parents else (src, "")
    raw = _spec_parts(spec)
    if raw is None:
        raise BuildError(f"COPY --from source '{src}' escapes the source rootfs.")
    parts = tree.resolve(raw)
    st = tree.lstat(parts) if parts is not None else None
    if parts is None or st is None:
        raise BuildError(f"COPY --from source '{src}' not found in stage.")
    if parents:
        dest = _parents_dest(dest, _rel_name(raw), anchor)
        is_dir_dest = False
    _add_to_file_map(
        tree,
        parts,
        st,
        dest,
        is_dir_dest=is_dir_dest,
        file_map=file_map,
        uid=uid,
        gid=gid,
        mode_override=mode_override,
        auto_extract=False,
        src_rel=_rel_name(parts),
        ignore_patterns=(),
    )


def _declared_length(resp: typing.Any) -> int:
    """The body length *resp* declares, or 0 when it declares none.

    A header is a string the remote chose, so `int()` on one is this program's
    own contribution to the problem: `Content-Length: abc` is a ValueError, and
    an ADD's net is around network failures, not around that. http.client itself
    treats a length it cannot parse as absent and reads until the connection
    closes, so this answers the same way.
    """
    try:
        value = int(resp.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


def _copy_url(
    url: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    spool: _Spool,
) -> None:
    """ADD URL: download the file to dest.

    Streamed onto disk rather than read whole: how much a URL answers with is
    the remote's choice, and the response used to be held in memory until the
    whole instruction was packed.

    A body that ends short of the length it declared is not the file the
    Dockerfile asked for, and nothing downstream would notice: there is no
    digest to check an ADD against, so the short bytes went into the rootfs and
    into the layer `push` uploads under the name of the whole file. The framing
    is why the check has to be here: a truncated *chunked* body raises
    IncompleteRead on its own, while a truncated **Content-Length** one raises
    nothing at all, CPython's HTTPResponse.read(amt) declining to for
    compatibility.

    That IncompleteRead is also why the net catches http.client.HTTPException:
    urllib wraps what it can into URLError, which is an OSError, but
    http.client's own family for a response that is malformed or cut short is
    not one, and used to walk out of here and out of `build` as a traceback.
    """
    if dest.endswith("/"):
        name = os.path.basename(urllib.parse.urlparse(url).path) or "index"
        arcname = dest.lstrip("/") + name
    else:
        arcname = dest.lstrip("/")
    opener = urllib.request.build_opener(AuthStrippingRedirectHandler)
    try:
        with opener.open(url) as resp:
            declared = _declared_length(resp)
            spooled, written = spool.stream(resp)
            if declared and written < declared:
                raise BuildError(f"ADD {url}: the response ended after {written} of {declared} bytes.")
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise BuildError(f"ADD {url}: {exc}") from exc
    _spool_entry(
        file_map,
        arcname,
        spool,
        spooled,
        mode_override if mode_override is not None else 0o644,
        uid,
        gid,
        int(time.time()),
    )


def _add_to_file_map(
    tree: _SourceTree,
    parts: typing.Sequence[str],
    st: os.stat_result,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    auto_extract: bool,
    src_rel: str,
    ignore_patterns: typing.Iterable[str],
    spool: _Spool | None = None,
) -> None:
    """Record the source *parts* names in *tree*, by what the lstat says.

    A symlink is copied as a symlink (never read through), a directory is walked,
    and a regular file is recorded, or, for ADD, unpacked when it turns out to be
    an archive. Devices, FIFOs and sockets are skipped, as they are everywhere
    else in the program.
    """
    if stat.S_ISLNK(st.st_mode):
        _add_symlink(tree, parts, st, dest, is_dir_dest, file_map, uid, gid)
        return
    if stat.S_ISDIR(st.st_mode):
        _add_directory_tree(
            tree,
            parts,
            dest,
            file_map,
            uid,
            gid,
            mode_override,
            src_rel,
            ignore_patterns,
        )
        return
    if stat.S_ISREG(st.st_mode):
        if auto_extract:
            assert spool is not None
            if _extract_archive(tree, parts, dest, file_map, uid, gid, spool):
                return
        _add_regular(tree, parts, st, dest, is_dir_dest, file_map, uid, gid, mode_override)


def _add_regular(
    tree: _SourceTree,
    parts: typing.Sequence[str],
    st: os.stat_result,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
) -> None:
    arcname = _dest_arcname(parts[-1], dest, is_dir_dest)
    mode = mode_override if mode_override is not None else stat.S_IMODE(st.st_mode)
    _file_entry(file_map, arcname, tree.root, parts, mode, uid, gid, int(st.st_mtime), st.st_size, tree.root_fd)


def _add_symlink(
    tree: _SourceTree,
    parts: typing.Sequence[str],
    st: os.stat_result,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
) -> None:
    arcname = _dest_arcname(parts[-1], dest, is_dir_dest)
    try:
        fd = tree.opendir(parts[:-1])
    except OSError:
        return
    try:
        target = os.readlink(parts[-1], dir_fd=fd)
    except OSError:
        return
    finally:
        os.close(fd)
    file_map[arcname] = {
        "kind": "symlink",
        "target": target,
        "mode": 0o777,
        "uid": uid,
        "gid": gid,
        "mtime": int(st.st_mtime),
    }


def _add_directory_tree(
    tree: _SourceTree,
    parts: typing.Sequence[str],
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    src_rel: str,
    ignore_patterns: typing.Iterable[str],
) -> None:
    """Record everything under the directory *parts* names.

    When the source is a directory its entries themselves go into dest, so the
    destination is treated as a directory.

    The walk carries directory descriptors on an explicit stack, one level opened
    O_NOFOLLOW off the one above: a symlink is recorded as a symlink and never
    descended (what os.walk(followlinks=False) gave), and how deep the tree goes
    is the context's business rather than the interpreter's. Only the fds along
    the current path are open, and past dirfd.MAX_OPEN_LEVELS of them the
    shallowest levels are parked, so a source tree thousands deep does not spend
    a descriptor per level.

    Frame layout: [fd, None, pending names, rel components, owned].
    """
    if not dest.endswith("/"):
        dest = dest + "/"
    patterns = list(ignore_patterns)
    try:
        top_fd = tree.opendir(parts)
    except OSError:
        return
    prefix = list(parts)
    stack: list[dirfd._Frame] = [[top_fd, None, None, (), True]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, pending, rel_parts, owned = frame
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
            try:
                st = dirfd.lstat_at(fd, name)
            except OSError:
                continue
            child = (*rel_parts, name)
            arc = _make_subpath(dest, "/".join(rel_parts), name).lstrip("/")
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                # Not put through .dockerignore: a pattern matching a directory
                # already matches everything under it (is_ignored counts a match
                # on any parent), and a `!` line re-including one entry of an
                # ignored directory only survives if the walk goes in.
                file_map[arc] = {
                    "kind": "dir",
                    "mode": mode_override if mode_override is not None else stat.S_IMODE(mode),
                    "uid": uid,
                    "gid": gid,
                    "mtime": 0,
                }
                try:
                    sub = dirfd.opendir_at(fd, name)
                except OSError:
                    continue
                levels.push([sub, None, None, child, True])
                continue
            combined = src_rel + "/" + "/".join(child) if src_rel and src_rel != os.curdir else "/".join(child)
            if is_ignored(combined, patterns):
                continue
            if stat.S_ISLNK(mode):
                try:
                    target = os.readlink(name, dir_fd=fd)
                except OSError:
                    continue
                file_map[arc] = {
                    "kind": "symlink",
                    "target": target,
                    "mode": 0o777,
                    "uid": uid,
                    "gid": gid,
                    "mtime": int(st.st_mtime),
                }
            elif stat.S_ISREG(mode):
                _file_entry(
                    file_map,
                    arc,
                    tree.root,
                    prefix + list(child),
                    mode_override if mode_override is not None else stat.S_IMODE(mode),
                    uid,
                    gid,
                    int(st.st_mtime),
                    st.st_size,
                    tree.root_fd,
                )
            # Other types intentionally skipped (devices, FIFOs, sockets).
    except BaseException:
        dirfd.close_frames(stack)
        raise


def _make_subpath(dest: str, rel: str, name: str) -> str:
    parts = [dest.rstrip("/")]
    if rel and rel != ".":
        parts.append(rel)
    if name:
        parts.append(name)
    return "/".join(p.strip("/") for p in parts if p is not None)


def _dest_arcname(src_full: str, dest: str, is_dir_dest: bool) -> str:
    if is_dir_dest or dest.endswith("/"):
        base = os.path.basename(src_full.rstrip("/"))
        return (dest.rstrip("/") + "/" + base).lstrip("/")
    return dest.lstrip("/")


def _extract_archive(
    tree: _SourceTree,
    parts: typing.Sequence[str],
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    spool: _Spool,
) -> int:
    """ADD auto-extract: unpack *parts* into dest when it is a tar.

    How many members were recorded; zero means it was not an archive after all
    and the caller copies the source verbatim (see _extract_tar_into_dest).
    Sniffed and read through a single descriptor on the file, so the archive that
    gets unpacked is the inode the walk found and not whatever the name leads to
    by the time tarfile opens it.
    """
    try:
        fd, _st = tree.open_file(parts)
    except OSError:
        return 0
    try:
        with open(fd, "rb", closefd=False) as fh:
            if not is_tar_header(fh.read(TAR_HEADER_BYTES)):
                return 0
            fh.seek(0)
            return _extract_tar_into_dest(fh, os.path.join(tree.root, *parts), dest, file_map, uid, gid, spool)
    finally:
        os.close(fd)


def _extract_tar_into_dest(
    fobj: typing.IO[bytes],
    src_name: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    spool: _Spool,
) -> int:
    """ADD auto-extract: stream the tar in *fobj* into dest as a tree.

    Returns how many members were recorded. Zero means the stream was not an
    archive after all: it failed on its very first header, or it held nothing
    this records (an empty tar; one of nothing but devices, FIFOs and traversal
    names). The caller reads that as "copy the source verbatim", which is what
    Docker does with a file its own archive probe rejects. That matters because
    the sniff that gets a source here is a signature and a signature is all it
    can be: gzip, bzip2 and xz magic say "compressed", not "compressed *tar*",
    so a plain data.gz is indistinguishable from a data.tar.gz until tarfile
    reads a header. A failure *after* members were recorded is the other thing,
    a real archive, truncated or corrupt, with half of itself already in the
    file_map, and that ends the build naming the source.

    Every regular member is spooled to its own file. Reading them into the
    file_map instead meant the archive's entire uncompressed content sat in
    memory at once, and the archive is whatever the Dockerfile pointed ADD
    at, which for a URL source is not even local.
    """
    if not dest.endswith("/"):
        dest = dest + "/"
    recorded = 0
    try:
        with tarfile.open(fileobj=fobj, mode="r|*") as tf:
            for m in tf:
                if m.isblk() or m.ischr() or m.isfifo():
                    continue
                # Strip a literal leading './' prefix. lstrip("./") would eat
                # any combination of dots and slashes and silently neutralise
                # './../foo' style traversal entries.
                rel = m.name
                while rel.startswith("./"):
                    rel = rel[2:]
                rel = rel.lstrip("/")
                if any(p in ("..", ".", "") for p in rel.split("/")):
                    continue
                arc = (dest + rel).lstrip("/")
                if m.isdir():
                    file_map[arc] = {
                        "kind": "dir",
                        "mode": stat.S_IMODE(m.mode) or 0o755,
                        "uid": uid,
                        "gid": gid,
                        "mtime": int(m.mtime),
                    }
                elif m.issym():
                    file_map[arc] = {
                        "kind": "symlink",
                        "target": m.linkname,
                        "mode": 0o777,
                        "uid": uid,
                        "gid": gid,
                        "mtime": int(m.mtime),
                    }
                elif m.isreg():
                    member = tf.extractfile(m)
                    if member is None:
                        continue
                    spooled, _written = spool.stream(member)
                    _spool_entry(
                        file_map,
                        arc,
                        spool,
                        spooled,
                        stat.S_IMODE(m.mode) or 0o644,
                        uid,
                        gid,
                        int(m.mtime),
                    )
                else:
                    continue
                recorded += 1
    except tarfile.TarError as exc:
        if recorded:
            raise BuildError(f"ADD: cannot extract '{src_name}': {exc}.") from exc
        # Nothing was recorded, so there is nothing to undo and nothing in the
        # file_map to disagree with the file the caller records instead.
        return 0
    return recorded


def _open_dest_dir(rootfs_dir: str, rootfs_fd: int | None, resolved: typing.Sequence[str]) -> int | None:
    """A descriptor on the *resolved* directory under the rootfs, creating it.

    Walked down from the stage's own descriptor when it has one, so the
    directory the entry lands in is inside the rootfs the stage was created
    against; by name only for a rootfs the caller made itself.
    """
    if rootfs_fd is None:
        return dirfd.opendir_under(rootfs_dir, resolved, create=True)
    try:
        return dirfd.descend_at(rootfs_fd, resolved, create=True)
    except OSError:
        return None


def _materialise_files(rootfs_dir: str, file_map: dict[str, typing.Any], *, rootfs_fd: int | None = None) -> None:
    """Apply file_map entries to rootfs_dir on disk.

    Sorting the arcnames guarantees every parent is materialised before
    its children, so a symlink entry lands before anything written
    "through" it. The destination's parent is then resolved with
    safe_resolve_parts, which follows existing symlink components but
    clamps each hop inside rootfs_dir. Otherwise an ADD'd tar (or a
    stage) could ship `evil -> /` followed by `evil/passwd` and the write
    would escape onto the host.

    The resolve says where the entry belongs; it does not make writing
    there safe on its own, because it decides that by name and everything
    afterwards used the answer by name too. os.makedirs(), os.remove(),
    shutil.copyfile() and os.chmod() all resolve the path again, so a
    component re-pointed in between, by a background process an earlier
    RUN left running, which nothing kills off Termux, sent the whole
    instruction wherever the new link led. The parent is therefore
    re-walked off a descriptor (dirfd.opendir_under, O_NOFOLLOW per
    level, creating what is missing) and the entry itself is written as
    (dir_fd, name).

    The final component is deliberately not resolved, so we replace the
    entry itself and never a same-named symlink's target, which means
    every kind has to drop a link standing there first, the directory
    branch included.

    The reading half is the same bargain: a file entry's bytes come out of a
    descriptor MapSources walks down from the tree the source was found in, never
    out of a path composed from it.

    *rootfs_fd* is the rootfs itself when the caller has pinned it, and then even
    the walk's first hop resolves no name: the rootfs of a build stage is a name
    inside the build's scratch tree, so moving the tree aside and leaving a link
    under the name would redirect every write this makes.
    """
    with MapSources() as sources:
        for arcname in sorted(file_map.keys()):
            entry = file_map[arcname]
            parts = [p for p in arcname.split("/") if p not in ("", ".")]
            if not parts or ".." in parts:
                continue
            resolved = safe_resolve_parts(rootfs_dir, parts[:-1], root_fd=rootfs_fd)
            if resolved is None:
                continue

            dir_fd = _open_dest_dir(rootfs_dir, rootfs_fd, resolved)
            if dir_fd is None:
                raise BuildError(
                    f"Failed to write '{arcname}' into rootfs: '{'/'.join(resolved)}' is not a directory inside it"
                )
            try:
                _materialise_entry(dir_fd, parts[-1], entry, sources)
            except OSError as exc:
                raise BuildError(f"Failed to write '{arcname}' into rootfs: {exc}") from exc
            finally:
                os.close(dir_fd)


def _materialise_entry(
    dir_fd: int,
    name: str,
    entry: dict[str, typing.Any],
    sources: MapSources,
) -> None:
    """Write one file_map entry into the directory dir_fd refers to."""
    kind = entry["kind"]
    if kind == "dir":
        # A symlink already standing at this name would send both the mkdir and
        # the chmod to whatever it points at. The parent is resolved with
        # clamping but the final component is deliberately left alone, so
        # `etc -> /home/user` in the image plus an ADD'd tar carrying an `etc/`
        # member would chmod that host directory to the member's mode, leaving
        # the tree disagreeing with the layer, which records a plain directory
        # there. Overlay semantics replace a symlink with a real directory; the
        # tar extractor already drops it the same way (see tar_extract).
        try:
            st: os.stat_result | None = dirfd.lstat_at(dir_fd, name)
        except OSError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            dirfd.unlink_quietly(dir_fd, name)
        with contextlib.suppress(FileExistsError):
            os.mkdir(name, 0o777, dir_fd=dir_fd)
        # chmod_at opens O_PATH|O_NOFOLLOW and sets the mode on the descriptor:
        # fchmodat(2) has no AT_SYMLINK_NOFOLLOW, so naming the entry would hand
        # the mode to a link planted since the mkdir.
        dirfd.chmod_at(dir_fd, name, entry.get("mode", 0o755), only_dir=True)
    elif kind == "symlink":
        # symlink(2) has no O_TRUNC; whatever is there has to go first.
        dirfd.unlink_quietly(dir_fd, name)
        os.symlink(entry["target"], name, dir_fd=dir_fd)
    elif kind == "file":
        # open_new_at is O_EXCL and drops a leftover rather than adopting it, so
        # the bytes always land in a new inode inside this directory, never
        # through a hardlink to somewhere else, which is the one thing O_NOFOLLOW
        # cannot refuse.
        mode = entry.get("mode", 0o644)
        src_fd, _src_st = sources.open(entry)
        try:
            fd, _st = dirfd.open_new_at(dir_fd, name, mode)
            try:
                with (
                    open(src_fd, "rb", closefd=False) as src,
                    os.fdopen(fd, "wb", closefd=False) as dst,
                ):
                    shutil.copyfileobj(src, dst, _SPOOL_CHUNK)
                # Explicitly, because the mode open_new_at created the file with
                # went through the umask.
                with contextlib.suppress(OSError):
                    os.fchmod(fd, mode)
            finally:
                os.close(fd)
        finally:
            os.close(src_fd)
