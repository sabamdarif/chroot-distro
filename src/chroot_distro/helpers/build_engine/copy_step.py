import contextlib
import hashlib
import os
import re
import shlex
import shutil
import stat
import tarfile
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
)
from chroot_distro.helpers.build_engine.users import resolve_chown
from chroot_distro.helpers.docker import (
    AuthStrippingRedirectHandler,
    layer_cache_path,
    pull_image,
)
from chroot_distro.helpers.layer_diff import write_files_layer
from chroot_distro.message import log_info


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

    tokens = list(instr["value"]) if instr["exec_form"] else shlex.split(str(instr["value"]))
    if len(tokens) < 2:
        raise BuildError(
            f"{instr['name']} requires at least one source and a "
            f"destination at line {instr['lineno']}."
        )

    sources = tokens[:-1]
    dest = tokens[-1]

    # Reject BuildKit-only flags loudly.
    for k in flags:
        if k in ("link", "parents"):
            raise BuildError(
                f"{instr['name']} --{k} is a BuildKit-only flag and is "
                f"not supported (line {instr['lineno']})."
            )

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
    mode_override = (
        int(chmod, 8) if chmod and re.match(r"^[0-7]+$", chmod) else None
    )

    file_map: dict[str, typing.Any] = {}
    for kind, src in resolved:
        if kind == "url":
            _copy_url(src, dest, file_map, uid, gid, mode_override)
        elif kind == "ctx":
            _copy_from_context(
                engine, src, dest, is_dir_dest, file_map,
                uid, gid, mode_override, auto_extract,
            )
        elif kind == "rootfs":
            assert from_rootfs is not None
            _copy_from_rootfs(
                from_rootfs, src, dest, is_dir_dest, file_map,
                uid, gid, mode_override,
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
    stage.layers.append(
        {"digest": digest, "size": size, "diff_id": diff_id}
    )
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
) -> None:
    # Per Docker semantics, a leading '/' on a COPY/ADD source is
    # equivalent to no leading slash: both forms resolve relative
    # to the build context root.
    src_rel_raw = src.lstrip("/")

    full = os.path.normpath(os.path.join(engine.build_dir, src_rel_raw))
    if (full != engine.build_dir
            and not full.startswith(engine.build_dir + os.sep)):
        raise BuildError(
            f"COPY source '{src}' escapes the build context."
        )
    if not os.path.exists(full):
        matches = sorted(simple_glob(engine.build_dir, src_rel_raw))
        matches = [m for m in matches if not is_ignored(m, engine.ignore_patterns)]
        if not matches:
            raise BuildError(
                f"COPY/ADD source '{src}' not found in build context."
            )
        for m in matches:
            full_m = os.path.join(engine.build_dir, m)
            _add_to_file_map(
                full_m, dest, is_dir_dest=True, file_map=file_map,
                uid=uid, gid=gid, mode_override=mode_override,
                auto_extract=auto_extract, src_rel=m,
                ignore_patterns=engine.ignore_patterns,
            )
        return
    rel = os.path.relpath(full, engine.build_dir)
    if is_ignored(rel, engine.ignore_patterns):
        return
    _add_to_file_map(
        full, dest, is_dir_dest=is_dir_dest, file_map=file_map,
        uid=uid, gid=gid, mode_override=mode_override,
        auto_extract=auto_extract, src_rel=rel,
        ignore_patterns=engine.ignore_patterns,
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
) -> None:
    abs_rootfs = os.path.abspath(from_rootfs)
    full = os.path.normpath(os.path.join(abs_rootfs, src.lstrip("/")))
    if full != abs_rootfs and not full.startswith(abs_rootfs + os.sep):
        raise BuildError(
            f"COPY --from source '{src}' escapes the source rootfs."
        )
    if not os.path.lexists(full):
        raise BuildError(
            f"COPY --from source '{src}' not found in stage."
        )
    _add_to_file_map(
        full, dest, is_dir_dest=is_dir_dest, file_map=file_map,
        uid=uid, gid=gid, mode_override=mode_override,
        auto_extract=False, src_rel=src,
        ignore_patterns=(),
    )


def _copy_url(
    url: str,
    dest: str,
    file_map: dict[str, typing.Any],
    uid: int,
    gid: int,
    mode_override: int | None,
) -> None:
    """ADD URL: download the file to dest."""
    if dest.endswith("/"):
        name = os.path.basename(
            urllib.parse.urlparse(url).path
        ) or "index"
        arcname = (dest.lstrip("/") + name)
    else:
        arcname = dest.lstrip("/")
    opener = urllib.request.build_opener(AuthStrippingRedirectHandler)
    try:
        with opener.open(url) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise BuildError(f"ADD {url}: {exc}") from exc
    file_map[arcname] = {
        "kind": "content",
        "data": data,
        "mode": mode_override if mode_override is not None else 0o644,
        "uid": uid, "gid": gid, "mtime": int(time.time()),
    }


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
) -> None:
    if os.path.islink(src_full):
        _add_symlink(src_full, dest, is_dir_dest, file_map, uid, gid)
        return
    if os.path.isdir(src_full):
        _add_directory_tree(
            src_full, dest, file_map, uid, gid, mode_override, src_rel,
            ignore_patterns,
        )
        return
    if os.path.isfile(src_full):
        # Auto-extract tar archives for ADD.
        if auto_extract and is_tar_archive(src_full):
            _extract_tar_into_dest(src_full, dest, file_map, uid, gid)
            return
        _add_regular(
            src_full, dest, is_dir_dest, file_map,
            uid, gid, mode_override, src_rel,
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
        "kind": "file", "src": src_full,
        "mode": mode, "uid": uid, "gid": gid,
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
        "kind": "symlink", "target": target,
        "mode": 0o777, "uid": uid, "gid": gid,
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
                    "kind": "symlink", "target": tgt,
                    "mode": 0o777, "uid": uid, "gid": gid,
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
                    "uid": uid, "gid": gid, "mtime": 0,
                }
        for f in filenames:
            full = os.path.join(dirpath, f)
            src_relpath = os.path.relpath(full, src_full)
            combined_rel = (
                (src_rel + "/" + src_relpath)
                if src_rel and src_rel != "." else src_relpath
            )
            if is_ignored(combined_rel, list(ignore_patterns)):
                continue
            arc = _make_subpath(dest, rel, f).lstrip("/")
            if os.path.islink(full):
                try:
                    tgt = os.readlink(full)
                except OSError:
                    continue
                file_map[arc] = {
                    "kind": "symlink", "target": tgt,
                    "mode": 0o777, "uid": uid, "gid": gid,
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
                    "kind": "file", "src": full,
                    "mode": mode, "uid": uid, "gid": gid,
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
) -> None:
    """ADD auto-extract: stream the tar into dest as a tree."""
    if not dest.endswith("/"):
        dest = dest + "/"
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
                    "uid": uid, "gid": gid, "mtime": int(m.mtime),
                }
            elif m.issym():
                file_map[arc] = {
                    "kind": "symlink", "target": m.linkname,
                    "mode": 0o777, "uid": uid, "gid": gid,
                    "mtime": int(m.mtime),
                }
            elif m.isreg():
                fobj = tf.extractfile(m)
                if fobj is None:
                    continue
                data = fobj.read()
                file_map[arc] = {
                    "kind": "content", "data": data,
                    "mode": stat.S_IMODE(m.mode) or 0o644,
                    "uid": uid, "gid": gid, "mtime": int(m.mtime),
                }


def _materialise_files(rootfs_dir: str, file_map: dict[str, typing.Any]) -> None:
    """Apply file_map entries to rootfs_dir on disk."""
    for arcname in sorted(file_map.keys()):
        entry = file_map[arcname]
        host = os.path.join(rootfs_dir, arcname.lstrip("/"))
        parent = os.path.dirname(host)
        with contextlib.suppress(OSError):
            os.makedirs(parent, exist_ok=True)
        kind = entry["kind"]
        try:
            if kind == "dir":
                os.makedirs(host, exist_ok=True)
                with contextlib.suppress(OSError):
                    os.chmod(host, entry.get("mode", 0o755))
            elif kind == "symlink":
                if os.path.lexists(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                os.symlink(entry["target"], host)
            elif kind == "content":
                if os.path.lexists(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                with open(host, "wb") as fh:
                    fh.write(entry["data"])
                with contextlib.suppress(OSError):
                    os.chmod(host, entry.get("mode", 0o644))
            elif kind == "file":
                if os.path.lexists(host):
                    with contextlib.suppress(OSError):
                        os.remove(host)
                shutil.copyfile(entry["src"], host)
                with contextlib.suppress(OSError):
                    os.chmod(host, entry.get("mode", 0o644))
        except OSError as exc:
            raise BuildError(
                f"Failed to write '{arcname}' into rootfs: {exc}"
            ) from exc
