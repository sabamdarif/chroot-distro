import logging
import os
import shlex
import shutil
from dataclasses import dataclass, field

from chroot_distro.commands.login.passwd import resolve_rootfs_path
from chroot_distro.constants import IS_TERMUX, TERMUX_PREFIX
from chroot_distro.exceptions import ChrootDistroError

log = logging.getLogger(__name__)


@dataclass
class ChrootConfig:
    """Structured representation of a chroot invocation.

    Unlike :func:`build_chroot_args` which returns a command-line ``list[str]``
    for the GNU ``chroot`` binary, this dataclass carries the individual
    parameters so that :func:`chroot_distro.syscalls.chroot.chroot_and_exec`
    can be called directly without parsing them back out of a string.
    """

    rootfs: str
    command: list[str] = field(default_factory=list)
    uid: int | None = None
    gid: int | None = None
    groups: list[int] | None = None
    workdir: str = "/"
    env: dict[str, str] | None = None


def _find_rootfs_shell(rootfs: str) -> str | None:
    """Find a usable shell inside the container rootfs, returning its guest path.

    Uses chroot-aware symlink resolution so that absolute symlinks
    (e.g. Alpine's ``/bin/sh → /bin/busybox``) are followed within the
    rootfs namespace rather than escaping to the host filesystem.

    A shell that is only visible because of a bind-mounted host ``$PREFIX``
    (e.g. distroless / rootless images on Termux) is rejected, so the caller
    falls back to running the command directly instead of exec'ing a host
    binary that the chroot cannot resolve.
    """
    rootfs_real = os.path.realpath(rootfs)
    for guest_path in ("/bin/sh", f"{TERMUX_PREFIX}/bin/sh", f"{TERMUX_PREFIX}/bin/bash"):
        sh_path = os.path.join(rootfs, guest_path.lstrip("/"))
        # Fast path: regular file, no symlink resolution needed.
        if os.path.isfile(sh_path) and not os.path.islink(sh_path):
            return guest_path
        # Chroot-aware resolution: follows symlinks within the rootfs
        # namespace so absolute targets (e.g. /bin/busybox) are resolved
        # relative to rootfs, not the host root.
        try:
            resolved = resolve_rootfs_path(rootfs, guest_path)
        except OSError:
            continue
        # Accept only when the resolved target is a real file inside rootfs.
        if os.path.isfile(resolved) and os.path.commonpath([rootfs_real, resolved]) == rootfs_real:
            return guest_path
    return None


def build_chroot_args(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    workdir: str = "",
    inner_cmd: list[str] | None = None,
    is_run: bool = False,
) -> list[str]:
    """Build the command line arguments for the GNU chroot command.

    GNU chroot's ``--skip-chdir`` is only valid when NEWROOT is ``/``,
    so we cannot use it for our containers.  Instead, when *workdir* is
    set we wrap the inner command with ``sh -c 'cd <dir> && exec …'``
    so the directory change happens **inside** the chroot namespace.

    For distroless / rootless images that lack ``/bin/sh``, the ``cd``
    wrapper is skipped and the command is executed directly (with the
    working directory defaulting to ``/``).
    """
    chroot_exe = None
    if IS_TERMUX:
        termux_chroot = os.path.join(TERMUX_PREFIX, "bin", "chroot")
        if os.path.isfile(termux_chroot):
            chroot_exe = termux_chroot
    if not chroot_exe:
        chroot_exe = shutil.which("chroot")
    if not chroot_exe:
        raise ChrootDistroError(
            "Required executable 'chroot' not found on the system. Please ensure it is in your PATH."
        )

    args = [chroot_exe]

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

    # 4. Inner command — optionally prefixed with a cd into workdir.
    #
    # For `run` (executing an image's Entrypoint/Cmd), the command is run
    # directly and must never be wrapped in a shell: rootless/distroless
    # images have no usable in-rootfs shell, and on Termux the host
    # $PREFIX/bin/sh is visible inside the rootfs via the bind-mounted
    # /data, which would make chroot try to exec a shell that the chroot
    # cannot resolve ('.../sh: No such file or directory').
    cmd = list(inner_cmd) if inner_cmd else []
    if workdir and workdir != "/" and not is_run:
        shell_path = _find_rootfs_shell(rootfs)
        if shell_path:
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
            args.extend([shell_path, "-c", wrapped])
        else:
            # Distroless / rootless image without a shell — cannot wrap
            # with a shell to change directory.  Run the command directly;
            # the working directory will default to /.
            log.debug(
                "No usable shell in rootfs %s; skipping workdir cd to %s",
                rootfs,
                workdir,
            )
            args.extend(cmd)
    else:
        args.extend(cmd)

    return args


def build_chroot_config(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    workdir: str = "",
    inner_cmd: list[str] | None = None,
    is_run: bool = False,
) -> ChrootConfig:
    """Build a :class:`ChrootConfig` for native chroot execution.

    The signature mirrors :func:`build_chroot_args` so callers can
    construct both the legacy command-list and the structured config
    from the same parameters.  The ``ChrootConfig`` is consumed by
    :func:`chroot_distro.syscalls.chroot.chroot_and_exec`.
    """
    uid: int | None = None
    gid: int | None = None
    parsed_groups: list[int] | None = None

    if login_uid is not None:
        try:
            uid = int(login_uid)
        except (ValueError, TypeError):
            pass

    if login_gid is not None:
        try:
            gid = int(login_gid)
        except (ValueError, TypeError):
            pass

    if groups:
        parsed_groups = []
        for g in groups:
            try:
                parsed_groups.append(int(g))
            except (ValueError, TypeError):
                pass

    # Resolve inner command with workdir wrapping (same logic as build_chroot_args).
    cmd = list(inner_cmd) if inner_cmd else []
    effective_wd = workdir if workdir else "/"

    if workdir and workdir != "/" and not is_run:
        shell_path = _find_rootfs_shell(rootfs)
        if shell_path:
            quoted_workdir = shlex.quote(workdir)
            wrapped = (
                f"cd {quoted_workdir} 2>/dev/null || cd /; exec {shlex.join(cmd)}"
                if cmd
                else f"cd {quoted_workdir} 2>/dev/null || cd /"
            )
            cmd = [shell_path, "-c", wrapped]
            effective_wd = "/"  # cd is handled inside the shell wrapper
        else:
            log.debug(
                "No usable shell in rootfs %s; skipping workdir cd to %s",
                rootfs,
                workdir,
            )
            effective_wd = "/"

    return ChrootConfig(
        rootfs=rootfs,
        command=cmd,
        uid=uid,
        gid=gid,
        groups=parsed_groups,
        workdir=effective_wd,
    )

