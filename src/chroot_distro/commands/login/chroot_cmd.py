def build_chroot_args(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    skip_chdir: bool = False,
    inner_cmd: list[str] | None = None,
) -> list[str]:
    """Build the command line arguments for the GNU chroot command."""
    args = ["chroot"]

    # 1. Handle user and group specifications
    if login_uid is not None:
        userspec = str(login_uid)
        if login_gid is not None:
            userspec += f":{login_gid}"
        args.append(f"--userspec={userspec}")

    # 2. Handle supplementary groups
    if groups:
        # Convert all to strings and join by commas
        group_str = ",".join(str(g) for g in groups)
        args.append(f"--groups={group_str}")

    # 3. Handle skip-chdir option
    if skip_chdir:
        args.append("--skip-chdir")

    # 4. Rootfs target directory
    args.append(rootfs)

    # 5. Inner command to run inside chroot
    if inner_cmd:
        args.extend(inner_cmd)

    return args
