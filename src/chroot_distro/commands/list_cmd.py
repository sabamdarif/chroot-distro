# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro list`: what is installed, how big it is, whether it is in use.

No lock is taken. `list` runs unelevated on Termux, and `container_busy_status` reads
a lock file's holder line instead of trying for the lock, so a busy container is
reported without making anyone wait. The picture is a moment's snapshot, which is all
a listing can be.

A directory carrying the `.install-incomplete` marker is not a container: it is
listed separately, with the two commands that resolve it, rather than being offered
as usable.

`_rootfs_size_bytes` is `du -sb -x` in Python, apparent sizes from lstat and pruning
at a filesystem boundary, so a mount under the rootfs is not counted into the
container's own size. `_ensure_manifest_readable` widens a manifest a rooted install
left mode 0600, because the unelevated Termux run cannot otherwise read the image
reference out of it, and nothing in that file is secret.

`_read_manifest_info` opens the manifest once and both the table row and the
`--json` document read that one record, so the SOURCE column and the JSON `source`
field cannot drift. `--json` always carries the detail `-v` prints, since a
consumer should not have to know which flag adds a field.
"""

import errno
import json
import os
import typing
from dataclasses import dataclass

from chroot_distro.constants import CONTAINERS_DIR, PROGRAM_NAME
from chroot_distro.locking import container_busy_status
from chroot_distro.message import C, emit_json, msg, warn
from chroot_distro.paths import container_manifest, container_rootfs, is_install_incomplete
from chroot_distro.progress import fmt_size, loading_line


@dataclass(frozen=True)
class _ManifestInfo:
    """What `manifest.json` says about one container, read once per row.

    `source` is the display string `list`'s SOURCE column shows, kept here so
    the column and the JSON field cannot disagree: `"ref (arch)"` for an image
    reference, `"local archive"` when the manifest names none, `"unknown"` when
    it could not be parsed.
    """

    source: str = "local archive"
    image_ref: str = ""
    arch: str = ""
    source_url: str = ""
    image_type: str = ""
    user: str = ""
    workdir: str = ""
    ports: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ContainerRow:
    name: str
    size: str
    source: str
    status: str
    size_bytes: int = 0
    manifest: _ManifestInfo = _ManifestInfo()


def _iter_container_names() -> tuple[list[str], list[str]]:
    """Return (installed, incomplete) container names, each sorted.

    A directory carrying the .install-incomplete marker is a leftover from
    an interrupted install, not an installed container. It is reported
    separately so `list` can mention it without presenting it as usable.
    """
    try:
        entries = sorted(e for e in os.listdir(CONTAINERS_DIR) if os.path.isdir(container_rootfs(e)))
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            warn(f"Permission denied: cannot read containers directory '{CONTAINERS_DIR}'")
        elif exc.errno != errno.ENOENT:
            warn(f"Failed to list containers directory '{CONTAINERS_DIR}': {exc}")
        return [], []
    installed = [e for e in entries if not is_install_incomplete(e)]
    incomplete = [e for e in entries if is_install_incomplete(e)]
    return installed, incomplete


def _same_device(path: str, dev: int) -> bool:
    """Return True if *path* is on the same device as *dev*."""
    try:
        return os.lstat(path).st_dev == dev
    except OSError:
        return False


def _rootfs_size_bytes(rootfs: str) -> int:
    """Calculate total apparent size in bytes, staying on one filesystem.

    Equivalent to ``du -sb -x -- <rootfs>`` but without the external binary.
    Uses ``os.lstat()`` to get apparent file sizes and respects filesystem
    boundaries (the ``-x`` flag behavior).
    """
    try:
        root_dev = os.lstat(rootfs).st_dev
    except OSError as exc:
        warn(f"Failed to stat rootfs directory '{rootfs}': {exc}")
        return 0

    total = 0
    for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
        # -x behavior: prune directories on different filesystems
        dirnames[:] = [d for d in dirnames if _same_device(os.path.join(dirpath, d), root_dev)]
        try:
            total += os.lstat(dirpath).st_size
        except OSError as exc:
            warn(f"Failed to lstat directory '{dirpath}': {exc}")
        # Count all files (and symlinks, sockets, etc.)
        for filename in filenames:
            fpath = os.path.join(dirpath, filename)
            try:
                total += os.lstat(fpath).st_size
            except OSError as exc:
                warn(f"Failed to lstat file '{fpath}': {exc}")
                continue
    return total


def _ensure_manifest_readable(manifest_path: str) -> None:
    """Raise readability of legacy ``0o600`` manifests (mkstemp default).

    Installs that ran as root left manifests unreadable to the Termux app user
    when ``list`` runs without elevation. World-readable ``0o644`` is safe here
    (no credentials in manifest.json).
    """
    try:
        st = os.stat(manifest_path)
    except OSError as exc:
        warn(f"Failed to stat manifest '{manifest_path}': {exc}")
        return
    if st.st_mode & 0o004:
        return
    try:
        os.chmod(manifest_path, (st.st_mode & 0o777) | 0o644)
    except OSError as exc:
        warn(f"Failed to change permissions on manifest '{manifest_path}': {exc}")


def _read_manifest_info(name: str) -> _ManifestInfo:
    """Read the manifest once and resolve both the display source and the fields.

    A manifest that cannot be read is not a failure of `list`: the container is
    still installed, so the row reports what it knows and the reason goes to a
    warning.
    """
    manifest_path = container_manifest(name)
    if not os.path.isfile(manifest_path):
        return _ManifestInfo()
    _ensure_manifest_readable(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return _ManifestInfo(source=name)
        warn(f"Failed to read manifest '{manifest_path}': {exc}")
        return _ManifestInfo(source="unknown")
    try:
        data: dict[str, typing.Any] = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        warn(f"Failed to parse manifest '{manifest_path}': {exc}")
        return _ManifestInfo(source="unknown")

    cfg = (data.get("image_config") or {}).get("config") or {}
    labels = cfg.get("Labels") or {}
    image_ref = str(data.get("image_ref") or "")
    arch = str(data.get("arch") or "")
    if not image_ref:
        source = "local archive"
    elif arch:
        source = f"{image_ref} ({arch})"
    else:
        source = image_ref
    return _ManifestInfo(
        source=source,
        image_ref=image_ref,
        arch=arch,
        source_url=labels.get("org.opencontainers.image.source", ""),
        image_type=labels.get("IMAGE_TYPE", ""),
        user=cfg.get("User", ""),
        workdir=cfg.get("WorkingDir", ""),
        ports=tuple(sorted((cfg.get("ExposedPorts") or {}).keys())),
    )


def _read_image_source(name: str) -> str:
    return _read_manifest_info(name).source


def _container_row(name: str) -> _ContainerRow:
    rootfs = container_rootfs(name)
    size_bytes = 0
    try:
        size_bytes = _rootfs_size_bytes(rootfs)
        size = fmt_size(size_bytes)
    except OSError as exc:
        warn(f"Failed to calculate rootfs size for '{name}': {exc}")
        size = "?"
    manifest = _read_manifest_info(name)
    return _ContainerRow(
        name=name,
        size=size,
        source=manifest.source,
        status=container_busy_status(name),
        size_bytes=size_bytes,
        manifest=manifest,
    )


def _format_table(rows: list[_ContainerRow]) -> list[str]:
    name_w = max(len("NAME"), *(len(r.name) for r in rows))
    size_w = max(len("SIZE"), *(len(r.size) for r in rows))
    source_w = max(len("SOURCE"), *(len(r.source) for r in rows))
    status_w = max(len("STATUS"), *(len(r.status) for r in rows))

    lines = [
        f"  {C['BCYAN']}{'NAME':<{name_w}}  {'SIZE':>{size_w}}  {'SOURCE':<{source_w}}  {'STATUS':<{status_w}}{C['RST']}",
    ]
    for row in rows:
        status_color = "YELLOW" if row.status.startswith("in use") else "GREEN"
        lines.append(
            f"  {C['GREEN']}{row.name:<{name_w}}{C['RST']}  "
            f"{C['CYAN']}{row.size:>{size_w}}{C['RST']}  "
            f"{row.source:<{source_w}}  "
            f"{C[status_color]}{row.status:<{status_w}}{C['RST']}"
        )
    return lines


def _row_document(row: _ContainerRow) -> dict[str, typing.Any]:
    """One container as `--json` shows it: numbers stay numbers, flags stay booleans."""
    m = row.manifest
    return {
        "name": row.name,
        "size": row.size,
        "size_bytes": row.size_bytes,
        "status": row.status,
        "in_use": row.status.startswith("in use"),
        "source": row.source,
        "image_ref": m.image_ref or None,
        "arch": m.arch or None,
        "source_url": m.source_url or None,
        "image_type": m.image_type or None,
        "user": m.user or None,
        "workdir": m.workdir or None,
        "ports": list(m.ports),
    }


def command_list(args) -> None:
    """List every container directory that contains a rootfs/."""
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    json_mode = getattr(args, "json", False)
    entries, incomplete = _iter_container_names()

    if quiet:
        for name in entries:
            print(name)
        return

    if json_mode:
        documents = [_row_document(_container_row(name)) for name in entries]
        emit_json("list", {"containers": documents, "incomplete": incomplete})
        return

    msg()
    if not entries:
        msg(f"{C['YELLOW']}No containers are installed.{C['RST']}")
        msg()
        msg(f"{C['CYAN']}Install one with: {C['GREEN']}{PROGRAM_NAME} install ubuntu:25.10{C['RST']}")
    else:
        rows: list[_ContainerRow] = []
        total = len(entries)
        with loading_line("Gathering container info...") as update:
            for index, name in enumerate(entries, start=1):
                update(f"Scanning {name} ({index}/{total})...")
                rows.append(_container_row(name))
        msg(f"{C['CYAN']}Installed containers:{C['RST']}")
        msg()
        for line in _format_table(rows):
            msg(line)
        if verbose:
            msg()
            for row in rows:
                info = row.manifest
                has_detail = any(
                    [
                        info.source_url,
                        info.image_type,
                        info.user,
                        info.workdir,
                        info.ports,
                    ]
                )
                if not has_detail:
                    continue
                msg(f"  {C['GREEN']}{row.name}{C['RST']}:")
                if info.source_url:
                    msg(f"    {C['CYAN']}Source:{C['RST']}  {info.source_url}")
                if info.image_type:
                    msg(f"    {C['CYAN']}Type:{C['RST']}    {info.image_type}")
                if info.user:
                    msg(f"    {C['CYAN']}User:{C['RST']}    {info.user}")
                if info.workdir:
                    msg(f"    {C['CYAN']}WorkDir:{C['RST']} {info.workdir}")
                if info.ports:
                    msg(f"    {C['CYAN']}Ports:{C['RST']}   {', '.join(info.ports)}")
        msg()
        msg(f"{C['CYAN']}Log in with: {C['GREEN']}{PROGRAM_NAME} login <name>{C['RST']}")
    if incomplete:
        msg()
        names = ", ".join(incomplete)
        msg(f"{C['YELLOW']}Interrupted install(s) (not usable): {names}{C['RST']}")
        msg(
            f"{C['CYAN']}Re-run {C['GREEN']}{PROGRAM_NAME} install <ref> --name <name>{C['CYAN']} "
            f"to redo, or {C['GREEN']}{PROGRAM_NAME} remove <name>{C['CYAN']} to clean up.{C['RST']}"
        )
    msg()
