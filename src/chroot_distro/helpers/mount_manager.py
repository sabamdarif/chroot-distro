from __future__ import annotations

import contextlib
import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING

from chroot_distro.exceptions import MountError
from chroot_distro.message import warn

if TYPE_CHECKING:
    from chroot_distro.helpers.namespace import NamespaceHolder

log = logging.getLogger(__name__)


def decode_mount_path(path: str) -> str:
    """Decode octal escape sequences (like \\040 for space) in /proc/mounts paths."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def _mounts_under_rootfs_from_lines(lines: list[str], rootfs: str) -> list[str]:
    rootfs_abs = os.path.realpath(rootfs)
    active_mounts: list[str] = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        mount_point = decode_mount_path(parts[1])
        try:
            mount_point_abs = os.path.realpath(mount_point)
        except OSError:
            continue
        if mount_point_abs == rootfs_abs or mount_point_abs.startswith(rootfs_abs + os.sep):
            active_mounts.append(mount_point_abs)
    active_mounts.sort(key=lambda p: len(p.split(os.sep)), reverse=True)
    return active_mounts


def _read_proc_mounts_lines(holder: NamespaceHolder | None) -> list[str]:
    if holder is not None:
        text = holder.get_proc_mounts()
        return text.splitlines() if text else []
    if not os.path.exists("/proc/mounts"):
        return []
    try:
        with open("/proc/mounts") as f:
            return f.readlines()
    except OSError as e:
        raise MountError(f"Failed to read /proc/mounts: {e}") from e


def get_active_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> list[str]:
    """Parse /proc/mounts and return mount points under rootfs (deepest first)."""
    lines = _read_proc_mounts_lines(holder)
    return _mounts_under_rootfs_from_lines(lines, rootfs)


def is_mounted(target: str, holder: NamespaceHolder | None = None) -> bool:
    """Check if a specific path is currently a mount point."""
    if holder is not None:
        return holder.is_mounted(target)

    target_abs = os.path.realpath(target)
    if not os.path.exists("/proc/mounts"):
        return False

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                mount_point = decode_mount_path(parts[1])
                if os.path.realpath(mount_point) == target_abs:
                    return True
    except OSError:
        pass
    return False


def _run_mount_cmd(cmd: list[str], holder: NamespaceHolder | None) -> subprocess.CompletedProcess:
    if holder is not None:
        return holder.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def safe_mount(source: str, target: str, holder: NamespaceHolder | None = None) -> None:
    """Safely mount source to target using bind mount.

    Creates target directory or file if they do not exist.
    """
    source_abs = os.path.realpath(source)
    if not os.path.exists(source_abs):
        raise MountError(f"Mount source does not exist: {source}")

    if os.path.isdir(source_abs):
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target):
            open(target, "a").close()

    if is_mounted(target, holder=holder):
        return

    try:
        result = _run_mount_cmd(["mount", "--bind", source_abs, target], holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        raise MountError(f"Failed to mount {source} to {target}: {stderr}") from e


def safe_unmount(target: str, holder: NamespaceHolder | None = None) -> None:
    """Safely unmount a target path.

    Falls back to lazy unmount if normal unmount fails.
    """
    if not is_mounted(target, holder=holder):
        return

    try:
        result = _run_mount_cmd(["umount", target], holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        warn(f"Standard umount failed for {target} ({stderr}). Trying lazy umount...")
        try:
            result = _run_mount_cmd(["umount", "-l", target], holder)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    result.args,
                    result.stdout,
                    result.stderr,
                )
        except subprocess.CalledProcessError as e_lazy:
            lazy_stderr = (e_lazy.stderr or "").strip() if hasattr(e_lazy, "stderr") else ""
            raise MountError(f"Failed to unmount {target} (lazy umount also failed): {lazy_stderr}") from e_lazy


def unmount_all(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Unmount all active mount points nested under rootfs in correct order."""
    mounts = get_active_mounts(rootfs, holder=holder)
    for m in mounts:
        safe_unmount(m, holder=holder)


def ensure_no_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Verify that no mount points exist under rootfs.

    Attempts to clean up if some are found. Raises MountError if any remain.
    """
    mounts = get_active_mounts(rootfs, holder=holder)
    if not mounts:
        return

    warn(f"Active mounts found under rootfs: {mounts}. Attempting automatic unmount...")
    with contextlib.suppress(MountError):
        unmount_all(rootfs, holder=holder)

    remaining = get_active_mounts(rootfs, holder=holder)
    if remaining:
        raise MountError(
            f"Safety check failed: Active mount points remain under {rootfs}: {remaining}. "
            "Refusing to delete or modify files in this directory to prevent host filesystem data loss."
        )


def _fs_supported(fstype: str) -> bool:
    """Return True if the kernel reports support for the given filesystem type."""
    try:
        with open("/proc/filesystems") as f:
            return fstype in f.read()
    except OSError:
        return False


def apply_special_mount(rootfs: str, sm, holder: NamespaceHolder | None = None) -> bool:
    """Execute a single SpecialMount inside rootfs.

    Returns True on success, False on failure (when optional=True).
    Raises RuntimeError on failure when optional=False.
    """
    if sm.check and not _fs_supported(sm.check):
        log.debug(f"Skipping {sm.fstype} mount: '{sm.check}' not in /proc/filesystems")
        return False

    target = os.path.join(rootfs, sm.target.lstrip("/"))

    if sm.mkdir:
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as e:
            msg = f"Failed to create mount target directory {target}: {e}"
            if sm.optional:
                log.debug(msg)
                return False
            raise RuntimeError(msg) from e
    elif not os.path.exists(target):
        log.debug(f"Mount target {target} does not exist and mkdir=False, skipping")
        return False

    if is_mounted(target, holder=holder):
        return True

    cmd = ["mount", "-t", sm.fstype]
    if sm.options:
        cmd += ["-o", sm.options]
    cmd += [sm.source, target]

    try:
        if holder is not None:
            result = holder.run(cmd, capture_output=True, text=True, timeout=15)
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        msg = f"mount timeout for {sm.fstype} at {target}"
        if sm.optional:
            log.debug(msg)
            return False
        raise RuntimeError(msg) from exc

    if result.returncode != 0:
        msg = f"mount -t {sm.fstype} failed: {result.stderr.strip()}"
        if sm.optional:
            log.debug(msg)
            return False
        raise RuntimeError(msg)

    log.debug(f"Mounted {sm.fstype} at {sm.target}")
    return True
