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


def resolve_host_home(login_user: str | None = None) -> str | None:
    """Host path to bind for ``--shared-home``.

    The guest ``--user`` name (e.g. ``saba``) often does not exist on the host
    (e.g. ``sabamdarif``). Prefer the account that invoked the tool (``SUDO_USER``,
    real uid, ``LOGNAME``). Only use ``$HOME`` for a root login.
    """
    import pwd

    if not login_user or login_user == "root":
        return os.environ.get("HOME") or os.path.expanduser("~")

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except (KeyError, OSError):
            pass

    if os.getuid() != 0:
        try:
            return pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError):
            pass

    for env_name in ("LOGNAME", "USER"):
        name = os.environ.get(env_name)
        if name and name != "root":
            try:
                return pwd.getpwnam(name).pw_dir
            except (KeyError, OSError):
                continue

    if login_user:
        try:
            return pwd.getpwnam(login_user).pw_dir
        except (KeyError, OSError):
            pass

    return None


def _next_free_uid(rootfs: str, reserved: set[int]) -> int:
    """Return a uid not present in container ``/etc/passwd`` or *reserved*."""
    used = set(reserved)
    try:
        passwd_path = resolve_rootfs_path(rootfs, "/etc/passwd")
        with open(passwd_path) as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    used.add(int(parts[2]))
    except OSError:
        pass
    candidate = 1001
    while candidate in used:
        candidate += 1
    return candidate


def release_passwd_uid_conflicts(
    rootfs: str,
    keep_username: str,
    uid: int,
    gid: int,
) -> bool:
    """Move other passwd entries off (*uid*, *gid*) after *keep_username* claims them."""
    try:
        passwd_path = resolve_rootfs_path(rootfs, "/etc/passwd")
        with open(passwd_path) as fh:
            lines = fh.readlines()
    except OSError:
        return False

    uid_s = str(uid)
    changed = False
    for line in lines:
        parts = line.rstrip("\n").split(":")
        if len(parts) < 3 or parts[0] == keep_username:
            continue
        if parts[2] != uid_s:
            continue
        if parts[0] == "root":
            new_uid, new_gid = 0, 0
        else:
            new_uid = _next_free_uid(rootfs, {uid, 0})
            new_gid = new_uid
        if set_passwd_uid_gid(rootfs, parts[0], new_uid, new_gid):
            changed = True
    return changed


def sync_passwd_to_path_owner(
    rootfs: str,
    username: str,
    host_path: str,
) -> bool:
    """Match passwd uid/gid to the owner of a host path (bind-mount source)."""
    if not host_path:
        return False
    if username == "root":
        return False
    try:
        st = os.stat(host_path)
    except OSError:
        return False
    try:
        if os.path.realpath(host_path) == os.path.realpath("/root"):
            return False
    except OSError:
        pass
    set_passwd_uid_gid(rootfs, username, st.st_uid, st.st_gid)
    release_passwd_uid_conflicts(
        rootfs, username, st.st_uid, st.st_gid,
    )
    return True


def sync_passwd_to_home_owner(
    rootfs: str,
    username: str,
    home_guest_path: str,
) -> bool:
    """Match passwd uid/gid to the on-disk home directory owner inside rootfs.

    After ``--termux-home``, passwd may still list the Termux app uid while the
    container's real ``/home/user`` tree on disk is owned by the original distro ids.
    """
    if not home_guest_path or home_guest_path == "/":
        return False
    try:
        home_host = resolve_rootfs_path(rootfs, home_guest_path)
    except OSError:
        return False
    return sync_passwd_to_path_owner(rootfs, username, home_host)


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
