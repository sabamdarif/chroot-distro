import contextlib
import os
import re
import subprocess

from chroot_distro.exceptions import MountError
from chroot_distro.message import warn


def decode_mount_path(path: str) -> str:
    """Decode octal escape sequences (like \\040 for space) in /proc/mounts paths."""
    return re.sub(
        r'\\([0-7]{3})',
        lambda m: chr(int(m.group(1), 8)),
        path
    )

def get_active_mounts(rootfs: str) -> list[str]:
    """Parse /proc/mounts and return all active mount points nested under or equal to rootfs.

    Returned list is sorted by path depth descending (deepest mount points first)
    to facilitate clean, in-order unmounting.
    """
    rootfs_abs = os.path.realpath(rootfs)
    active_mounts = []

    if not os.path.exists("/proc/mounts"):
        return []

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                mount_point = decode_mount_path(parts[1])
                mount_point_abs = os.path.realpath(mount_point)

                # Check if mount point is exactly rootfs or nested inside rootfs
                if mount_point_abs == rootfs_abs or mount_point_abs.startswith(rootfs_abs + os.sep):
                    active_mounts.append(mount_point_abs)
    except OSError as e:
        raise MountError(f"Failed to read /proc/mounts: {e}") from e

    # Sort deepest first (by number of path components, descending)
    active_mounts.sort(key=lambda p: len(p.split(os.sep)), reverse=True)
    return active_mounts

def is_mounted(target: str) -> bool:
    """Check if a specific path is currently a mount point."""
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

def safe_mount(source: str, target: str) -> None:
    """Safely mount source to target using bind mount.

    Creates target directory or file if they do not exist.
    """
    source_abs = os.path.realpath(source)
    if not os.path.exists(source_abs):
        raise MountError(f"Mount source does not exist: {source}")

    # Create target mount point
    if os.path.isdir(source_abs):
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target):
            open(target, "a").close()

    # Check if already mounted
    if is_mounted(target):
        return

    try:
        subprocess.run(
            ["mount", "--bind", source_abs, target],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        raise MountError(f"Failed to mount {source} to {target}: {e.stderr.strip()}") from e

def safe_unmount(target: str) -> None:
    """Safely unmount a target path.

    Falls back to lazy unmount if normal unmount fails.
    """
    if not is_mounted(target):
        return

    try:
        subprocess.run(
            ["umount", target],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        warn(f"Standard umount failed for {target} ({e.stderr.strip()}). Trying lazy umount...")
        try:
            subprocess.run(
                ["umount", "-l", target],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e_lazy:
            raise MountError(f"Failed to unmount {target} (lazy umount also failed): {e_lazy.stderr.strip()}") from e_lazy

def unmount_all(rootfs: str) -> None:
    """Unmount all active mount points nested under rootfs in correct order."""
    mounts = get_active_mounts(rootfs)
    for m in mounts:
        safe_unmount(m)

def ensure_no_mounts(rootfs: str) -> None:
    """Verify that no mount points exist under rootfs.

    Attempts to clean up if some are found. Raises MountError if any remain.
    """
    mounts = get_active_mounts(rootfs)
    if not mounts:
        return

    warn(f"Active mounts found under rootfs: {mounts}. Attempting automatic unmount...")
    with contextlib.suppress(MountError):
        unmount_all(rootfs)

    remaining = get_active_mounts(rootfs)
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


def apply_special_mount(rootfs: str, sm) -> bool:
    """Execute a single SpecialMount inside rootfs.

    Returns True on success, False on failure (when optional=True).
    Raises RuntimeError on failure when optional=False.
    """
    # Kernel check
    if sm.check and not _fs_supported(sm.check):
        warn(f"Skipping {sm.fstype} mount: '{sm.check}' not in /proc/filesystems")
        return False

    target = os.path.join(rootfs, sm.target.lstrip("/"))

    # Create mount point inside rootfs
    if sm.mkdir:
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as e:
            msg = f"Failed to create mount target directory {target}: {e}"
            if sm.optional:
                warn(msg)
                return False
            raise RuntimeError(msg) from e
    elif not os.path.exists(target):
        warn(f"Mount target {target} does not exist and mkdir=False, skipping")
        return False

    # Check if already mounted
    if is_mounted(target):
        return True

    # Build mount command
    cmd = ["mount", "-t", sm.fstype]
    if sm.options:
        cmd += ["-o", sm.options]
    cmd += [sm.source, target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        msg = f"mount timeout for {sm.fstype} at {target}"
        if sm.optional:
            warn(msg)
            return False
        raise RuntimeError(msg)

    if result.returncode != 0:
        msg = f"mount -t {sm.fstype} failed: {result.stderr.strip()}"
        if sm.optional:
            warn(msg)
            return False
        raise RuntimeError(msg)

    from chroot_distro.message import log_info
    log_info(f"Mounted {sm.fstype} at {sm.target}")
    return True

