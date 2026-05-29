import shlex


def build_chroot_args(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    workdir: str = "",
    inner_cmd: list[str] | None = None,
) -> list[str]:
    """Build the command line arguments for the GNU chroot command.

    GNU chroot's ``--skip-chdir`` is only valid when NEWROOT is ``/``,
    so we cannot use it for our containers.  Instead, when *workdir* is
    set we wrap the inner command with ``sh -c 'cd <dir> && exec …'``
    so the directory change happens **inside** the chroot namespace.
    """
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

    # 3. Rootfs target directory
    args.append(rootfs)

    # 4. Inner command — optionally prefixed with a cd into workdir
    cmd = list(inner_cmd) if inner_cmd else []
    if workdir and workdir != "/":
        # Wrap the inner command so 'cd' happens inside the chroot.
        # If the directory doesn't exist or is inaccessible, we fall back to /
        # to ensure the shell still starts successfully.
        # exec replaces the shell process to keep the PID tree clean.
        quoted_workdir = shlex.quote(workdir)
        wrapped = (
            f"cd {quoted_workdir} 2>/dev/null || cd /; exec {shlex.join(cmd)}"
            if cmd
            else f"cd {quoted_workdir} 2>/dev/null || cd /"
        )
        args.extend(["/bin/sh", "-c", wrapped])
    else:
        args.extend(cmd)

    return args

