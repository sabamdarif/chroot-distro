# No file_map entry ever holds content in memory. A file_map covers a whole
# instruction at once, so ADD used to read an entire URL response — and then
# every regular member of an auto-extracted archive, all of them live at the
# same time — into RAM, and one instruction could take the build process out.
# Content that does not already exist as a file is spooled into engine.tmp_root
# and referenced by path, which is where it was headed anyway: the instruction
# both materialises it into the rootfs and packs it into a layer, and tmp_root
# is removed when the build ends.

import contextlib
import hashlib
import os
import re
import shutil
import stat
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile
import tempfile
import time
import typing
import urllib.error
import urllib.parse
import urllib.request

from chroot_distro.helpers.build_engine.dockerignore import (
    is_ignored,
    simple_glob,
)
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.parsing import (
    is_tar_archive,
    looks_like_url,
    split_operands,
)
from chroot_distro.helpers.build_engine.users import resolve_chown
from chroot_distro.helpers.docker import (
    AuthStrippingRedirectHandler,
    layer_cache_path,
    pull_image,
)
from chroot_distro.helpers.layer_diff import write_files_layer
from chroot_distro.helpers.tar_extract import _safe_resolve
from chroot_distro.message import log_info

# Chunk size for spooling, the same one tar_extract streams with.
_SPOOL_CHUNK = 1 << 17


def _spool_dir(engine: typing.Any) -> str:
    """The build's scratch directory for ADD content, created on demand."""
    path = os.path.join(engine.tmp_root, "add-spool")
    os.makedirs(path, exist_ok=True)
    return path


def _spool_stream(fobj: typing.IO[bytes], spool: str) -> str:
    """Copy *fobj* into a fresh file under *spool*; return its path."""
    fd, path = tempfile.mkstemp(dir=spool, prefix="add-")
    try:
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(fobj, out, _SPOOL_CHUNK)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    return path


def _spool_entry(
    file_map: dict[str, typing.Any],
    arcname: str,
    path: str,
    mode: int,
    uid: int,
    gid: int,
    mtime: int,
) -> None:
    """Record a spooled file in *file_map* as an ordinary file entry.

    The timestamp goes on the spool file itself because that is where both
    consumers read it from: layer_diff's "file" kind takes an entry's mode,
    uid and gid from the dict but its mtime from the file on disk. The value
    came out of an archive header or off the clock, so it can be any number
    at all -- os.utime() raises OverflowError, not OSError, on one the
    platform cannot store.
    """
    with contextlib.suppress(OSError, OverflowError, ValueError):
        os.utime(path, (mtime, mtime))
    file_map[arcname] = {
        "kind": "file",
        "src": path,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
    }


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

    # Whitelist flags; reject everything else loudly (never silently ignore).
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
                f"{instr['name']} --{k} is not supported (line {instr['lineno']}); "
                f"refusing to silently ignore it."
            )
    parents = "parents" in flags

    chown = flags.get("chown")
    chmod = flags.get("chmod")
    from_stage = flags.get("from")
    from_rootfs = None
    if from_stage:
        ref_stage = engine.stages.get(from_stage)
        from_rootfs = _pull_throwaway_image(engine, from_stage) if ref_stage is None else ref_stage.rootfs_dir

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

    uid, gid = resolve_chown(stage.rootfs_dir, chown) if chown else (0, 0)
    mode_override = int(chmod, 8) if chmod and re.match(r"^[0-7]+$", chmod) else None

    file_map: dict[str, typing.Any] = {}
    spool = _spool_dir(engine) if allow_url or auto_extract else None
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
            )

    if not file_map:
        return

    _materialise_files(stage.rootfs_dir, file_map)

    tmp_layer_path = os.path.join(
        engine.tmp_root,
        f"layer-{stage.index}-{len(stage.layers)}.tar.gz",
    )
    digest, size, diff_id = write_files_layer(file_map, tmp_layer_path)
    final_path = layer_cache_path(digest)
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    os.replace(tmp_layer_path, final_path)
    stage.layers.append({"digest": digest, "size": size, "diff_id": diff_id})
    stage.parent_layer_digest = digest


def _pull_throwaway_image(engine: typing.Any, image_ref: str) -> str:
    """Pull an external image into a tmp rootfs for COPY --from."""
    slot = hashlib.sha256(image_ref.encode()).hexdigest()[:16]
    rootfs = os.path.join(engine.tmp_root, "copyfrom-" + slot)
    if os.path.isdir(rootfs) and os.listdir(rootfs):
        return rootfs
    os.makedirs(rootfs, exist_ok=True)
    if not engine.quiet:
        log_info(f"COPY --from='{image_ref}': fetching external image...")
    try:
        pull_image(image_ref, rootfs, engine.target_arch_pd)
    except RuntimeError as exc:
        raise BuildError(f"COPY --from={image_ref}: {exc}") from exc
    return rootfs


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
    spool: str | None = None,
) -> None:
    # Per Docker semantics, a leading '/' on a COPY/ADD source is
    # equivalent to no leading slash: both forms resolve relative
    # to the build context root.
    src_rel_raw = src.lstrip("/")
    anchor = ""
    if parents:
        src_rel_raw, anchor = _split_parents_pivot(src_rel_raw)

    full = os.path.normpath(os.path.join(engine.build_dir, src_rel_raw))
    if full != engine.build_dir and not full.startswith(engine.build_dir + os.sep):
        raise BuildError(f"COPY source '{src}' escapes the build context.")
    if not os.path.exists(full):
        matches = sorted(simple_glob(engine.build_dir, src_rel_raw))
        matches = [m for m in matches if not is_ignored(m, engine.ignore_patterns)]
        if not matches:
            raise BuildError(f"COPY/ADD source '{src}' not found in build context.")
        for m in matches:
            full_m = os.path.join(engine.build_dir, m)
            _add_to_file_map(
                full_m,
                _parents_dest(dest, m, anchor) if parents else dest,
                is_dir_dest=not parents,
                file_map=file_map,
                uid=uid,
                gid=gid,
                mode_override=mode_override,
                auto_extract=auto_extract,
                src_rel=m,
                ignore_patterns=engine.ignore_patterns,
                spool=spool,
            )
        return
    rel = os.path.relpath(full, engine.build_dir)
    if is_ignored(rel, engine.ignore_patterns):
        return
    if parents:
        dest = _parents_dest(dest, rel, anchor)
        is_dir_dest = False
    _add_to_file_map(
        full,
        dest,
        is_dir_dest=is_dir_dest,
        file_map=file_map,
        uid=uid,
        gid=gid,
        mode_override=mode_override,
        auto_extract=auto_extract,
        src_rel=rel,
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
) -> None:
    src_rel = src.lstrip("/")
    anchor = ""
    if parents:
        src_rel, anchor = _split_parents_pivot(src_rel)
    abs_rootfs = os.path.abspath(from_rootfs)
    full = os.path.normpath(os.path.join(abs_rootfs, src_rel))
    if full != abs_rootfs and not full.startswith(abs_rootfs + os.sep):
        raise BuildError(f"COPY --from source '{src}' escapes the source rootfs.")
    if not os.path.lexists(full):
        raise BuildError(f"COPY --from source '{src}' not found in stage.")
    if parents:
        dest = _parents_dest(dest, os.path.relpath(full, abs_rootfs), anchor)
        is_dir_dest = False
    _add_to_file_map(
        full,
        dest,
        is_dir_dest=is_dir_dest,
        file_map=file_map,
        uid=uid,
        gid=gid,
        mode_override=mode_override,
        auto_extract=False,
        src_rel=src,
        ignore_patterns=(),
    )


def _copy_url(
    url: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    spool: str,
) -> None:
    """ADD URL: download the file to dest.

    Streamed onto disk rather than read whole: how much a URL answers with is
    the remote's choice, and the response used to be held in memory until the
    whole instruction was packed.
    """
    if dest.endswith("/"):
        name = os.path.basename(urllib.parse.urlparse(url).path) or "index"
        arcname = dest.lstrip("/") + name
    else:
        arcname = dest.lstrip("/")
    opener = urllib.request.build_opener(AuthStrippingRedirectHandler)
    try:
        with opener.open(url) as resp:
            path = _spool_stream(resp, spool)
    except (urllib.error.URLError, OSError) as exc:
        raise BuildError(f"ADD {url}: {exc}") from exc
    _spool_entry(
        file_map,
        arcname,
        path,
        mode_override if mode_override is not None else 0o644,
        uid,
        gid,
        int(time.time()),
    )


def _add_to_file_map(
    src_full: str,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    auto_extract: bool,
    src_rel: str,
    ignore_patterns: typing.Iterable[str],
    spool: str | None = None,
) -> None:
    if os.path.islink(src_full):
        _add_symlink(src_full, dest, is_dir_dest, file_map, uid, gid)
        return
    if os.path.isdir(src_full):
        _add_directory_tree(
            src_full,
            dest,
            file_map,
            uid,
            gid,
            mode_override,
            src_rel,
            ignore_patterns,
        )
        return
    if os.path.isfile(src_full):
        # Auto-extract tar archives for ADD.
        if auto_extract and is_tar_archive(src_full):
            assert spool is not None
            if _extract_tar_into_dest(src_full, dest, file_map, uid, gid, spool):
                return
        _add_regular(
            src_full,
            dest,
            is_dir_dest,
            file_map,
            uid,
            gid,
            mode_override,
            src_rel,
        )
        return


def _add_regular(
    src_full: str,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    src_rel: str,
) -> None:
    arcname = _dest_arcname(src_full, dest, is_dir_dest)
    try:
        mode = stat.S_IMODE(os.lstat(src_full).st_mode)
    except OSError:
        mode = 0o644
    if mode_override is not None:
        mode = mode_override
    file_map[arcname] = {
        "kind": "file",
        "src": src_full,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": int(os.lstat(src_full).st_mtime),
    }


def _add_symlink(
    src_full: str,
    dest: str,
    is_dir_dest: bool,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
) -> None:
    arcname = _dest_arcname(src_full, dest, is_dir_dest)
    try:
        target = os.readlink(src_full)
    except OSError:
        return
    file_map[arcname] = {
        "kind": "symlink",
        "target": target,
        "mode": 0o777,
        "uid": uid,
        "gid": gid,
        "mtime": int(os.lstat(src_full).st_mtime),
    }


def _add_directory_tree(
    src_full: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
    src_rel: str,
    ignore_patterns: typing.Iterable[str],
) -> None:
    # When source is a directory, the entries themselves go into
    # dest. The destination is treated as a directory.
    if not dest.endswith("/"):
        dest = dest + "/"
    for dirpath, dirnames, filenames in os.walk(src_full, followlinks=False):
        rel = os.path.relpath(dirpath, src_full)
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                arc = _make_subpath(dest, rel, d).lstrip("/")
                try:
                    tgt = os.readlink(full)
                except OSError:
                    continue
                file_map[arc] = {
                    "kind": "symlink",
                    "target": tgt,
                    "mode": 0o777,
                    "uid": uid,
                    "gid": gid,
                    "mtime": 0,
                }
                dirnames.remove(d)
        # Add the directory itself (except the root).
        if rel != ".":
            arc = _make_subpath(dest, rel, "").rstrip("/").lstrip("/")
            if arc:
                try:
                    mode = stat.S_IMODE(os.lstat(dirpath).st_mode)
                except OSError:
                    mode = 0o755
                file_map[arc] = {
                    "kind": "dir",
                    "mode": mode_override if mode_override is not None else mode,
                    "uid": uid,
                    "gid": gid,
                    "mtime": 0,
                }
        for f in filenames:
            full = os.path.join(dirpath, f)
            src_relpath = os.path.relpath(full, src_full)
            combined_rel = (src_rel + "/" + src_relpath) if src_rel and src_rel != "." else src_relpath
            if is_ignored(combined_rel, list(ignore_patterns)):
                continue
            arc = _make_subpath(dest, rel, f).lstrip("/")
            if os.path.islink(full):
                try:
                    tgt = os.readlink(full)
                except OSError:
                    continue
                file_map[arc] = {
                    "kind": "symlink",
                    "target": tgt,
                    "mode": 0o777,
                    "uid": uid,
                    "gid": gid,
                    "mtime": int(os.lstat(full).st_mtime),
                }
            else:
                try:
                    mode = stat.S_IMODE(os.lstat(full).st_mode)
                except OSError:
                    mode = 0o644
                if mode_override is not None:
                    mode = mode_override
                file_map[arc] = {
                    "kind": "file",
                    "src": full,
                    "mode": mode,
                    "uid": uid,
                    "gid": gid,
                    "mtime": int(os.lstat(full).st_mtime),
                }


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


def _extract_tar_into_dest(
    src_full: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    spool: str,
) -> int:
    """ADD auto-extract: stream the tar into dest as a tree.

    Returns how many members were recorded. Zero means the stream was not an
    archive after all -- it failed on its very first header, or it held
    nothing this records (an empty tar; one of nothing but devices, FIFOs and
    traversal names) -- and the caller reads that as "copy the source
    verbatim", which is what Docker does with a file its own archive probe
    rejects. That matters because the sniff that gets a source here is a
    signature and a signature is all it can be: gzip, bzip2 and xz magic say
    "compressed", not "compressed *tar*", so a plain data.gz is
    indistinguishable from a data.tar.gz until tarfile reads a header. A
    failure *after* members were recorded is the other thing -- a real
    archive, truncated or corrupt, with half of itself already in the
    file_map -- and that ends the build naming the source.

    Every regular member is spooled to its own file. Reading them into the
    file_map instead meant the archive's entire uncompressed content sat in
    memory at once, and the archive is whatever the Dockerfile pointed ADD
    at, which for a URL source is not even local.
    """
    if not dest.endswith("/"):
        dest = dest + "/"
    recorded = 0
    try:
        with tarfile.open(src_full, "r|*") as tf:
            for m in tf:
                if m.isblk() or m.ischr() or m.isfifo():
                    continue
                # Strip a literal leading './' prefix (not lstrip("./") — that
                # would eat any combination of dots and slashes and silently
                # neutralise './../foo' style traversal entries).
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
                    fobj = tf.extractfile(m)
                    if fobj is None:
                        continue
                    _spool_entry(
                        file_map,
                        arc,
                        _spool_stream(fobj, spool),
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
            raise BuildError(f"ADD: cannot extract '{src_full}': {exc}.") from exc
        # Nothing was recorded, so there is nothing to undo and nothing in the
        # file_map to disagree with the file the caller records instead.
        return 0
    return recorded


def _materialise_files(rootfs_dir: str, file_map: dict[str, typing.Any]) -> None:
    """Apply file_map entries to rootfs_dir on disk.

    Sorting the arcnames guarantees every parent is materialised before
    its children, so a symlink entry lands before anything written
    "through" it. The destination's parent is then resolved with
    _safe_resolve, which follows existing symlink components but clamps
    each hop inside rootfs_dir — otherwise an ADD'd tar (or a stage)
    could ship `evil -> /` followed by `evil/passwd` and the write would
    escape onto the host. The final component is left unresolved so we
    replace the entry itself, never a same-named symlink's target -- which
    means every kind has to drop a link standing there first, the directory
    branch included.
    """
    for arcname in sorted(file_map.keys()):
        entry = file_map[arcname]
        parts = [p for p in arcname.split("/") if p not in ("", ".")]
        if not parts or ".." in parts:
            continue
        parent = _safe_resolve(rootfs_dir, parts[:-1])
        if parent is None:
            continue
        host = os.path.join(parent, parts[-1])
        with contextlib.suppress(OSError):
            os.makedirs(parent, exist_ok=True)
        kind = entry["kind"]
        try:
            if kind == "dir":
                # A symlink already standing at this name would send both the
                # mkdir and the chmod to whatever it points at. The parent is
                # resolved with clamping but the final component is deliberately
                # left alone, so `etc -> /home/user` in the image plus an ADD'd
                # tar carrying an `etc/` member had that host directory chmod'ed
                # to the member's mode -- and the tree then disagreed with the
                # layer, which records a plain directory there. Overlay
                # semantics replace a symlink with a real directory; the tar
                # extractor already drops it the same way (see tar_extract), the
                # materialiser did not. The other kinds unlink whatever is in
                # the way already.
                if os.path.islink(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                os.makedirs(host, exist_ok=True)
                with contextlib.suppress(OSError):
                    os.chmod(host, entry.get("mode", 0o755))
            elif kind == "symlink":
                if os.path.lexists(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                os.symlink(entry["target"], host)
            elif kind == "file":
                if os.path.lexists(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                shutil.copyfile(entry["src"], host)
                with contextlib.suppress(OSError):
                    os.chmod(host, entry.get("mode", 0o644))
        except OSError as exc:
            raise BuildError(f"Failed to write '{arcname}' into rootfs: {exc}") from exc
