import errno
import os
import stat


def resolve_rootfs_path(rootfs: str, guest_path: str) -> str:
    """Resolve an absolute guest path to its real host path.

    Follows symlinks within the rootfs namespace.
    """
    for _ in range(40):
        host_path = rootfs + guest_path
        try:
            st = os.lstat(host_path)
        except OSError:
            raise
        if not stat.S_ISLNK(st.st_mode):
            return host_path
        target = os.readlink(host_path)
        if os.path.isabs(target):
            guest_path = os.path.normpath(target)
        else:
            guest_path = os.path.normpath(
                os.path.join(os.path.dirname(guest_path), target)
            )
    raise OSError(errno.ELOOP, "Too many levels of symbolic links", guest_path)


def read_passwd_field(rootfs: str, user: str, field_index: int) -> str:
    """Return a single colon-delimited field for *user* from /etc/passwd."""
    try:
        passwd = resolve_rootfs_path(rootfs, "/etc/passwd")
    except OSError:
        return ""
    try:
        with open(passwd) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if parts and parts[0] == user and len(parts) > field_index:
                    return parts[field_index]
    except OSError:
        pass
    return ""


def find_passwd_by_uid(rootfs: str, uid: str) -> tuple:
    """Return (home, shell, primary_gid) for the given UID, or ('','','')."""
    try:
        passwd = resolve_rootfs_path(rootfs, "/etc/passwd")
    except OSError:
        return ("", "", "")
    try:
        with open(passwd) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 7 and parts[2] == uid:
                    return (parts[5], parts[6], parts[3])
    except OSError:
        pass
    return ("", "", "")


def read_group_gid(rootfs: str, group: str) -> str:
    """Return the GID string for the named group from /etc/group, or ''."""
    try:
        group_file = resolve_rootfs_path(rootfs, "/etc/group")
    except OSError:
        return ""
    try:
        with open(group_file) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if parts and parts[0] == group and len(parts) > 2:
                    return parts[2]
    except OSError:
        pass
    return ""


def find_user_groups(rootfs: str, username: str, primary_gid: str) -> list[str]:
    """Return a list of group GIDs that the user belongs to (primary + supplementary)."""
    gids = []
    if primary_gid:
        gids.append(primary_gid)

    try:
        group_file = resolve_rootfs_path(rootfs, "/etc/group")
    except OSError:
        return gids

    try:
        with open(group_file) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    gid = parts[2]
                    users = parts[3].split(",") if parts[3] else []
                    if username in users and gid not in gids:
                        gids.append(gid)
    except OSError:
        pass
    return gids
