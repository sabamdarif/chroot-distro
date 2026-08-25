# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The Android-side adjustments a guest needs on Termux, and nothing on Linux.

Every entry point here returns immediately when `IS_TERMUX` is false, so a caller
does not have to ask.

Android carries its permissions in supplementary group ids, so a guest whose
`/etc/group` has never heard of them gets no network, no bluetooth and no audio
no matter what it is allowed to do: `configure_android_rootfs` adds the
`ANDROID_GROUPS` ids and puts `root` in each. `_apt` is handled separately
because apt on Debian and Ubuntu drops to that account to fetch, so `aid_inet`
becomes its primary group and its state directories are chowned to it.

Both account files are reached through `rootfs.guest_etc_path`, never joined:
termux-docker images ship `/etc/group` and `/etc/passwd` as absolute symlinks
into `/system/etc`, which resolve on the host to a read-only filesystem and
would fail the write with EROFS.

`termux_home_owner_ids` takes the app uid from the ownership of `TERMUX_HOME`
rather than `getuid()`, which is 0 by the time this runs. `ensure_data_suid`
clears nosuid, nodev and noexec from the host `/data`, which `sudo` in the guest
and apt's gpgv under `--shared-tmp` both need; a remount replaces the whole VFS
flag word, so the flags in force are read back from `/proc/mounts` first and the
filesystem's own options are passed through untouched.
"""

import logging
import os

from chroot_distro.constants import IS_TERMUX, TERMUX_HOME
from chroot_distro.message import warn
from chroot_distro.syscalls.mount import (
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_REMOUNT,
    _parse_and_split_mount_options,
    native_mount,
)

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


def ensure_data_suid() -> bool:
    """Remount host /data with suid+exec when nosuid or noexec is set.

    Required for sudo in chroot (nosuid) and for gpgv/apt to work
    when --shared-tmp bind-mounts $PREFIX/tmp as /tmp (noexec).

    A remount takes its whole VFS flag word from this one call, so the flags
    already in force are read back out of /proc/mounts and only nosuid, nodev
    and noexec are cleared.  Whatever in that option field is the filesystem's
    own (lazytime, seclabel, an f2fs tunable) goes back as mount(2) data
    untouched, since stripping it is what earns an EINVAL.
    """
    if not IS_TERMUX:
        return False

    entry = _read_data_mount()
    if not entry:
        log.debug("ensure_data_suid: /data not found in /proc/mounts")
        return False

    device, _mount_point, opts = entry
    if "nosuid" not in opts and "noexec" not in opts:
        return True

    flags, data = _parse_and_split_mount_options(opts)
    flags &= ~(MS_NOSUID | MS_NODEV | MS_NOEXEC)
    try:
        native_mount(device, "/data", None, MS_REMOUNT | flags, data or None)
    except OSError as exc:
        warn(f"Failed to enable SUID on /data (remount failed): {exc}")
        return False

    log.info("Remounted /data with suid enabled")
    return True


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


def configure_android_rootfs(rootfs: str) -> None:
    """Apply Android-specific configurations to the rootfs.

    Only executes if running on Android/Termux.
    """
    if not IS_TERMUX:
        return

    # Resolve through in-rootfs symlinks: termux-docker's /etc/group and
    # /etc/passwd are absolute symlinks into /system/etc, which must not be
    # followed on the host (read-only Android /system -> EROFS).
    from chroot_distro.helpers.rootfs import guest_etc_path

    group_path = guest_etc_path(rootfs, "/etc/group")
    if not os.path.exists(group_path):
        return

    existing_groups = {}
    try:
        with open(group_path) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    existing_groups[parts[0]] = parts
    except OSError:
        return

    has_apt = False
    passwd_path = guest_etc_path(rootfs, "/etc/passwd")
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path) as f:
                for line in f:
                    if line.startswith("_apt:"):
                        has_apt = True
                        break
        except OSError as exc:
            log.warning("Failed to read /etc/passwd in setup_android_permissions: %s", exc)

    modified = False
    for gname, gid in ANDROID_GROUPS.items():
        if gname not in existing_groups:
            # Format: group_name:password:GID:user_list
            users = ["root"]
            if has_apt and gname in ("aid_inet", "aid_net_raw"):
                users.append("_apt")
            existing_groups[gname] = [gname, "x", str(gid), ",".join(users)]
            modified = True
        else:
            parts = existing_groups[gname]
            users = parts[3].split(",") if len(parts) > 3 and parts[3] else []
            group_modified = False
            if "root" not in users:
                users.append("root")
                group_modified = True
            if has_apt and gname in ("aid_inet", "aid_net_raw") and "_apt" not in users:
                users.append("_apt")
                group_modified = True

            if group_modified:
                if len(parts) <= 3:
                    parts.append(",".join(users))
                else:
                    parts[3] = ",".join(users)
                modified = True

    if modified:
        try:
            with open(group_path, "w") as f:
                for parts in existing_groups.values():
                    f.write(":".join(parts) + "\n")
        except OSError as exc:
            log.warning("Failed to write /etc/group in setup_android_permissions: %s", exc)

    adduser_conf = os.path.join(rootfs, "etc", "adduser.conf")
    if os.path.exists(adduser_conf):
        try:
            has_extra_groups = False
            with open(adduser_conf) as f:
                for line in f:
                    if "EXTRA_GROUPS=" in line and "aid_inet" in line:
                        has_extra_groups = True
                        break
            if not has_extra_groups:
                with open(adduser_conf, "a") as f:
                    f.write('\nEXTRA_GROUPS="aid_inet aid_net_raw aid_bt_admin aid_bt_net"\n')
        except OSError as exc:
            log.warning("Failed to configure adduser.conf in setup_android_permissions: %s", exc)

    # apt on Debian/Ubuntu runs as _apt, which needs network access: make
    # aid_inet (3003) its primary group and let it own its own state dirs.
    if has_apt and os.path.exists(passwd_path):
        try:
            passwd_lines = []
            passwd_modified = False
            _apt_uid = 100
            with open(passwd_path) as f:
                for raw_line in f:
                    parts = raw_line.rstrip("\n").split(":")
                    out_line = raw_line
                    if parts and parts[0] == "_apt" and len(parts) >= 4:
                        _apt_uid = int(parts[2])
                        if parts[3] != "3003":
                            parts[3] = "3003"
                            out_line = ":".join(parts) + "\n"
                            passwd_modified = True
                    passwd_lines.append(out_line)
            if passwd_modified:
                with open(passwd_path, "w") as f:
                    f.writelines(passwd_lines)

            for apt_dir in ("var/lib/apt", "var/cache/apt"):
                full_apt_dir = os.path.join(rootfs, apt_dir)
                if os.path.exists(full_apt_dir):
                    try:
                        os.chown(full_apt_dir, _apt_uid, 3003)
                        for root, dirs, files in os.walk(full_apt_dir):
                            for d in dirs:
                                os.chown(os.path.join(root, d), _apt_uid, 3003)
                            for file in files:
                                os.chown(os.path.join(root, file), _apt_uid, 3003)
                    except Exception as exc:
                        log.warning("Failed to chown apt directory %s in setup_android_permissions: %s", apt_dir, exc)
        except OSError as exc:
            log.warning("Failed to update /etc/passwd in setup_android_permissions: %s", exc)
