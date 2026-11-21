# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The Android-side adjustments a guest needs on Termux, and nothing on Linux.

`configure_android_rootfs` returns immediately when `IS_TERMUX` is false.
The host ownership and mount readers also support diagnostics callers.

Android carries its permissions in supplementary group ids, so a guest whose
`/etc/group` has never heard of them gets no network, no bluetooth and no audio
no matter what it is allowed to do: `configure_android_rootfs` adds the
`ANDROID_GROUPS` ids and puts `root` in each. `_apt` is handled separately
because apt on Debian and Ubuntu drops to that account to fetch, so `aid_inet`
becomes its primary group and its state directories are chowned to it.

Account/config edits resolve guest symlinks inside a pinned rootfs and replace
files through guarded parent descriptors in `rootfs.edit_guest_file`. Apt
ownership uses a bounded descriptor walk, skipping symlinks, special files and
multiply linked files. A valid numeric UID is required before ownership changes.
A link-count check cannot exclude a new hardlink made after the check.

`termux_home_owner_ids` takes the app uid from the ownership of `TERMUX_HOME`
rather than `getuid()`, which is 0 by the time this runs. `_read_data_mount` is
read-only, for `info`; a login never remounts the host `/data`. The per-session
suid/exec bind that a nosuid rootfs needs lives in `mount_manager`, so the
device's mount flags stay as Android set them.
"""

import contextlib
import logging
import os
import stat
from typing import Any

from chroot_distro import dirfd
from chroot_distro.constants import IS_TERMUX, TERMUX_HOME

log = logging.getLogger(__name__)


def termux_home_owner_ids() -> tuple[int, int]:
    """Return (uid, gid) of the Termux app user that owns ``TERMUX_HOME``.

    Uses filesystem ownership so this stays correct when ``chroot-distro`` runs
    elevated (``getuid()`` may be 0 while the home directory is still owned by
    the Termux app UID).
    """
    st = os.stat(TERMUX_HOME)
    return st.st_uid, st.st_gid


def _read_data_mount() -> tuple[str, str, str] | None:
    """Return (device, mount_point, options) for host /data, or None."""
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "/data":
                    return parts[0], parts[1], parts[3]
    except OSError as exc:
        log.debug("Failed to read /proc/mounts: %s", exc)
    return None


ANDROID_GROUPS = {
    "aid_inet": 3003,
    "aid_net_raw": 3004,
    "aid_bluetooth": 1002,
    "aid_graphics": 1003,
    "aid_input": 1004,
    "aid_audio": 1005,
    "aid_video": 1006,
    "aid_drm": 1007,
    "aid_wifi": 1010,
    "aid_usb": 1018,
    "aid_bt_admin": 3001,
    "aid_bt_net": 3002,
    "aid_admin": 3005,
}


def configure_android_rootfs(rootfs: str, *, root_fd: int | None = None) -> None:
    """Configure Android groups and apt within the pinned guest on Termux."""
    if not IS_TERMUX:
        return

    from chroot_distro.helpers.rootfs import edit_guest_file

    try:
        with contextlib.ExitStack() as stack:
            root_fd = dirfd.opendir(rootfs) if root_fd is None else os.dup(root_fd)
            stack.callback(os.close, root_fd)
            has_apt = False
            try:
                with edit_guest_file(root_fd, "/etc/passwd") as fh:
                    has_apt = any(line.startswith("_apt:") for line in fh.getvalue().splitlines())
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError) as exc:
                log.warning("Failed to read guest /etc/passwd: %s", exc)

            with edit_guest_file(root_fd, "/etc/group") as fh:
                existing_groups = {}
                for line in fh.getvalue().splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        existing_groups[parts[0]] = parts
                for name, gid in ANDROID_GROUPS.items():
                    parts = existing_groups.setdefault(name, [name, "x", str(gid), ""])
                    if len(parts) == 3:
                        parts.append("")
                    users = parts[3].split(",") if parts[3] else []
                    if "root" not in users:
                        users.append("root")
                    if has_apt and name in ("aid_inet", "aid_net_raw") and "_apt" not in users:
                        users.append("_apt")
                    parts[3] = ",".join(users)
                fh.seek(0)
                fh.truncate()
                fh.write("".join(":".join(parts) + "\n" for parts in existing_groups.values()))

            try:
                with edit_guest_file(root_fd, "/etc/adduser.conf") as fh:
                    if not any("EXTRA_GROUPS=" in line and "aid_inet" in line for line in fh.getvalue().splitlines()):
                        fh.write('\nEXTRA_GROUPS="aid_inet aid_net_raw aid_bt_admin aid_bt_net"\n')
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError) as exc:
                log.warning("Failed to configure guest /etc/adduser.conf: %s", exc)

            if has_apt:
                _configure_apt(root_fd)
    except FileNotFoundError:
        return
    except (OSError, UnicodeError) as exc:
        log.warning("Failed to configure Android guest permissions: %s", exc)


def _configure_apt(root_fd: int) -> None:
    from chroot_distro.helpers.rootfs import edit_guest_file
    from chroot_distro.helpers.tar_extract import safe_resolve_parts_at

    try:
        apt_uid = None
        with edit_guest_file(root_fd, "/etc/passwd") as fh:
            lines = fh.getvalue().splitlines(keepends=True)
            for index, line in enumerate(lines):
                parts = line.rstrip("\n").split(":")
                if parts[0] != "_apt":
                    continue
                if len(parts) < 4 or not parts[2].isascii() or not parts[2].isdecimal():
                    raise ValueError("invalid _apt UID")
                uid = int(parts[2])
                if not 0 <= uid < 2**32 - 1:
                    raise ValueError("invalid _apt UID")
                apt_uid = uid
                if parts[3] != "3003":
                    parts[3] = "3003"
                    lines[index] = ":".join(parts) + "\n"
            fh.seek(0)
            fh.truncate()
            fh.writelines(lines)
        if apt_uid is None:
            return
        for path in ("var/lib/apt", "var/cache/apt"):
            try:
                resolved = safe_resolve_parts_at(root_fd, path.split("/"))
                if not resolved:
                    continue
                fd = dirfd.descend_at(root_fd, resolved)
                try:
                    _chown_apt_tree(fd, apt_uid)
                finally:
                    os.close(fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                log.warning("Failed to chown guest %s: %s", path, exc)
    except (OSError, UnicodeError, ValueError) as exc:
        log.warning("Failed to configure guest _apt account: %s", exc)


def _chown_apt_tree(root_fd: int, uid: int) -> None:
    """Chown pinned directories and unshared regular files, never link targets."""
    stack: list[list[Any]] = [[root_fd, None, None, False]]
    levels = dirfd.Levels(stack)
    try:
        while stack:
            frame = stack[-1]
            fd, _, pending, _ = frame
            if pending is None:
                os.fchown(fd, uid, 3003)
                pending = frame[2] = dirfd.listdir_at(fd)
            if not pending:
                levels.pop()
                if frame[-1]:
                    os.close(fd)
                continue
            name = pending.pop()
            mode = dirfd.lstat_at(fd, name).st_mode
            if stat.S_ISDIR(mode):
                sub = dirfd.opendir_at(fd, name)
                levels.push([sub, None, None, True])
            elif stat.S_ISREG(mode):
                child, _ = dirfd.open_regular_at(fd, name, os.O_RDONLY)
                try:
                    if os.fstat(child).st_nlink == 1:
                        os.fchown(child, uid, 3003)
                finally:
                    os.close(child)
    finally:
        dirfd.close_frames(stack)
