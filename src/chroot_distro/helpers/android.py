import logging
import os
import subprocess

from chroot_distro.constants import IS_TERMUX, TERMUX_HOME
from chroot_distro.message import warn

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
    except OSError:
        pass
    return None


def ensure_data_suid() -> bool:
    """Remount host /data with suid+exec when nosuid or noexec is set.

    Required for sudo in chroot (nosuid) and for gpgv/apt to work
    when --shared-tmp bind-mounts $PREFIX/tmp as /tmp (noexec).

    Only replaces nosuid/nodev/noexec flags; preserves other mount options to avoid
    EINVAL from stripping lazytime, seclabel, etc.
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

    new_opts = opts.replace("nosuid", "suid").replace("nodev", "dev").replace("noexec", "exec")
    mount_arg = f"remount,{new_opts}"
    mount_cmd = ["mount", "-o", mount_arg, device, "/data"]
    try:
        subprocess.run(
            mount_cmd,
            check=True,
            capture_output=True,
            text=True,
        )
        log.info("Remounted /data with suid enabled")
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        warn(f"Failed to enable SUID on /data (remount failed): {exc}")
        return False


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

    group_path = os.path.join(rootfs, "etc", "group")
    if not os.path.exists(group_path):
        return

    # 1. Read existing groups
    existing_groups = {}
    try:
        with open(group_path) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    existing_groups[parts[0]] = parts
    except OSError:
        return

    # 1.5 Check if _apt exists in passwd
    has_apt = False
    passwd_path = os.path.join(rootfs, "etc", "passwd")
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path) as f:
                for line in f:
                    if line.startswith("_apt:"):
                        has_apt = True
                        break
        except OSError:
            pass

    # 2. Add missing Android groups or append root (and _apt) to them
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
            # Group exists, ensure root and _apt are in user list
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
        except OSError:
            pass

    # 3. Add aid_inet/aid_net_raw to default user add config (etc/adduser.conf)
    adduser_conf = os.path.join(rootfs, "etc", "adduser.conf")
    if os.path.exists(adduser_conf):
        try:
            # Check if EXTRA_GROUPS is already configured
            has_extra_groups = False
            with open(adduser_conf) as f:
                for line in f:
                    if "EXTRA_GROUPS=" in line and "aid_inet" in line:
                        has_extra_groups = True
                        break
            if not has_extra_groups:
                with open(adduser_conf, "a") as f:
                    f.write('\nEXTRA_GROUPS="aid_inet aid_net_raw aid_bt_admin aid_bt_net"\n')
        except OSError:
            pass

    # 4. _apt permission fix for Debian/Ubuntu based distros
    if has_apt and os.path.exists(passwd_path):
        try:
            # 4a. Update _apt's primary GID to 3003 (aid_inet) in /etc/passwd
            passwd_lines = []
            passwd_modified = False
            _apt_uid = 100  # Default fallback
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

            # 4b. Chown apt directories
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
                    except Exception:
                        pass
        except OSError:
            pass
