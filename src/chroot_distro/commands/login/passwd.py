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


def set_passwd_uid_gid(
    rootfs: str,
    username: str,
    uid: int,
    gid: int,
) -> bool:
    """Update a user's uid/gid in container ``/etc/passwd`` and ``/etc/shadow``."""
    try:
        passwd_path = resolve_rootfs_path(rootfs, "/etc/passwd")
    except OSError:
        return False

    uid_s, gid_s = str(uid), str(gid)
    changed = False
    try:
        with open(passwd_path) as fh:
            lines = fh.readlines()
    except OSError:
        return False

    new_lines: list[str] = []
    for line in lines:
        parts = line.rstrip("\n").split(":")
        if not parts or parts[0] != username:
            new_lines.append(line)
            continue
        if len(parts) < 7:
            new_lines.append(line)
            continue
        if parts[2] == uid_s and parts[3] == gid_s:
            new_lines.append(line)
            continue
        parts[2] = uid_s
        parts[3] = gid_s
        new_lines.append(":".join(parts) + "\n")
        changed = True

    if not changed:
        return False

    try:
        with open(passwd_path, "w") as fh:
            fh.writelines(new_lines)
    except OSError:
        return False

    try:
        shadow_path = resolve_rootfs_path(rootfs, "/etc/shadow")
    except OSError:
        return True

    try:
        with open(shadow_path) as fh:
            shadow_lines = fh.readlines()
    except OSError:
        return True

    shadow_out: list[str] = []
    for line in shadow_lines:
        parts = line.rstrip("\n").split(":")
        if parts and parts[0] == username and len(parts) >= 4:
            parts[2] = uid_s
            parts[3] = gid_s
            shadow_out.append(":".join(parts) + "\n")
        else:
            shadow_out.append(line)

    try:
        with open(shadow_path, "w") as fh:
            fh.writelines(shadow_out)
    except OSError:
        pass
    return True


def align_user_to_termux_owner(
    rootfs: str,
    username: str,
    uid: int,
    gid: int,
) -> bool:
    """Map a container passwd user to the Termux app uid/gid for ``--termux-home``.

    proot-distro keeps ``HOME`` as the distro path (e.g. ``/home/saba``) and bind-mounts
    ``TERMUX_HOME`` onto it; the guest user must use the same numeric ids as the Termux
    app that owns those files.
    """
    return set_passwd_uid_gid(rootfs, username, uid, gid)


def sync_passwd_to_home_owner(
    rootfs: str,
    username: str,
    home_guest_path: str,
) -> bool:
    """Match passwd uid/gid to the on-disk home directory owner.

    After ``--termux-home``, passwd may still list the Termux app uid while the
    container's real ``/home/user`` tree on disk is owned by the original distro ids.
    """
    if not home_guest_path or home_guest_path == "/":
        return False
    try:
        home_host = resolve_rootfs_path(rootfs, home_guest_path)
        st = os.stat(home_host)
    except OSError:
        return False
    return set_passwd_uid_gid(rootfs, username, st.st_uid, st.st_gid)


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
