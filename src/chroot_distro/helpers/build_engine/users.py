import os


def resolve_id(rootfs_dir: str, name: str, is_group: bool, default: int) -> int:
    """Translate a user or group name into a numeric ID.

    Numeric strings pass through. Otherwise the name is looked up in
    the rootfs's own /etc/passwd or /etc/group (not the host's). Falls
    back to *default* on missing files or unknown names.
    """
    if not name:
        return default
    if name.isdigit():
        return int(name)
    path = os.path.join(
        rootfs_dir, "etc", "group" if is_group else "passwd",
    )
    try:
        with open(path) as fh:
            for line in fh:
                parts = line.split(":")
                if parts and parts[0] == name and len(parts) > 2:
                    try:
                        return int(parts[2])
                    except ValueError:
                        return default
    except OSError:
        pass
    return default


def resolve_chown(rootfs_dir: str, chown: str) -> tuple[int, int]:
    """Resolve --chown=user[:group] against the rootfs /etc/passwd."""
    if ":" in chown:
        user, group = chown.split(":", 1)
    else:
        user, group = chown, ""
    uid = resolve_id(rootfs_dir, user, is_group=False, default=0)
    gid = (
        resolve_id(rootfs_dir, group, is_group=True, default=uid)
        if group else uid
    )
    return uid, gid


def resolve_user_for_chroot(rootfs_dir: str, user_spec: str) -> tuple[int, int]:
    """Resolve a USER directive's value into a (uid, gid) pair."""
    if not user_spec:
        return (0, 0)
    spec = str(user_spec).strip()
    if ":" in spec:
        u, g = spec.split(":", 1)
    else:
        u, g = spec, ""
    uid = resolve_id(rootfs_dir, u, is_group=False, default=0)
    gid = (
        resolve_id(rootfs_dir, g, is_group=True, default=uid) if g else uid
    )
    return uid, gid
