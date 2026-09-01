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
"""

import errno
import json
import os
import typing
from dataclasses import dataclass

from chroot_distro.constants import CONTAINERS_DIR, PROGRAM_NAME
from chroot_distro.locking import container_busy_status
from chroot_distro.message import C, msg, warn
from chroot_distro.paths import container_manifest, container_rootfs, is_install_incomplete
from chroot_distro.progress import fmt_size, loading_line


@dataclass(frozen=True)
class _ContainerRow:
    name: str
    size: str
    source: str
    status: str


@dataclass(frozen=True)
class _VerboseInfo:
    source_url: str = ""
    image_type: str = ""
    default_user: str = ""
    workdir: str = ""
    exposed_ports: str = ""


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


def _read_verbose_info(name: str) -> _VerboseInfo:
    """Extract detailed image config fields from manifest.json."""
    manifest_path = container_manifest(name)
    if not os.path.isfile(manifest_path):
        return _VerboseInfo()
    _ensure_manifest_readable(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
    except (OSError, json.JSONDecodeError) as exc:
        warn(f"Failed to read or parse manifest '{manifest_path}': {exc}")
        return _VerboseInfo()
    cfg = (data.get("image_config") or {}).get("config") or {}
    labels = cfg.get("Labels") or {}
    source_url = labels.get("org.opencontainers.image.source", "")
    image_type = labels.get("IMAGE_TYPE", "")
    default_user = cfg.get("User", "")
    workdir = cfg.get("WorkingDir", "")
    ports_dict = cfg.get("ExposedPorts") or {}
    exposed_ports = ", ".join(sorted(ports_dict.keys())) if ports_dict else ""
    return _VerboseInfo(
        source_url=source_url,
        image_type=image_type,
        default_user=default_user,
        workdir=workdir,
        exposed_ports=exposed_ports,
    )


def _read_image_source(name: str) -> str:
    manifest_path = container_manifest(name)
    if not os.path.isfile(manifest_path):
        return "local archive"
    _ensure_manifest_readable(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            raw = fh.read()
        if not raw.strip():
            return "local archive"
        data: dict[str, typing.Any] = json.loads(raw)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return name
        warn(f"Failed to read manifest '{manifest_path}': {exc}")
        return "unknown"
    except json.JSONDecodeError as exc:
        warn(f"Failed to parse manifest '{manifest_path}': {exc}")
        return "unknown"
    image_ref = data.get("image_ref") or ""
    if not image_ref:
        return "local archive"
    arch = data.get("arch") or ""
    if arch:
        return f"{image_ref} ({arch})"
    return str(image_ref)


def _container_row(name: str) -> _ContainerRow:
    rootfs = container_rootfs(name)
    try:
        size = fmt_size(_rootfs_size_bytes(rootfs))
    except OSError as exc:
        warn(f"Failed to calculate rootfs size for '{name}': {exc}")
        size = "?"
    return _ContainerRow(
        name=name,
        size=size,
        source=_read_image_source(name),
        status=container_busy_status(name),
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


def command_list(args) -> None:
    """List every container directory that contains a rootfs/."""
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    entries, incomplete = _iter_container_names()

    if quiet:
        for name in entries:
            print(name)
        return

    msg()
    if not entries:
        msg(f"{C['YELLOW']}No containers are installed.{C['RST']}")
        msg()
        msg(f"{C['CYAN']}Install one with: {C['GREEN']}{PROGRAM_NAME} install ubuntu:25.10{C['RST']}")
    else:
        rows: list[_ContainerRow] = []
        verbose_infos: dict[str, _VerboseInfo] = {}
        total = len(entries)
        with loading_line("Gathering container info...") as update:
            for index, name in enumerate(entries, start=1):
                update(f"Scanning {name} ({index}/{total})...")
                rows.append(_container_row(name))
                if verbose:
                    verbose_infos[name] = _read_verbose_info(name)
        msg(f"{C['CYAN']}Installed containers:{C['RST']}")
        msg()
        for line in _format_table(rows):
            msg(line)
        if verbose:
            msg()
            for row in rows:
                info = verbose_infos.get(row.name)
                if not info:
                    continue
                has_detail = any(
                    [
                        info.source_url,
                        info.image_type,
                        info.default_user,
                        info.workdir,
                        info.exposed_ports,
                    ]
                )
                if not has_detail:
                    continue
                msg(f"  {C['GREEN']}{row.name}{C['RST']}:")
                if info.source_url:
                    msg(f"    {C['CYAN']}Source:{C['RST']}  {info.source_url}")
                if info.image_type:
                    msg(f"    {C['CYAN']}Type:{C['RST']}    {info.image_type}")
                if info.default_user:
                    msg(f"    {C['CYAN']}User:{C['RST']}    {info.default_user}")
                if info.workdir:
                    msg(f"    {C['CYAN']}WorkDir:{C['RST']} {info.workdir}")
                if info.exposed_ports:
                    msg(f"    {C['CYAN']}Ports:{C['RST']}   {info.exposed_ports}")
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
