import contextlib
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
    """Chroot invocation parameters for the native
    :func:`chroot_distro.syscalls.chroot.chroot_and_exec` path (vs the
    ``list[str]`` argv that :func:`build_chroot_args` builds for the GNU
    ``chroot`` binary)."""

    rootfs: str
    command: list[str] = field(default_factory=list)
    uid: int | None = None
    gid: int | None = None
    groups: list[int] | None = None
    workdir: str = "/"
    env: dict[str, str] | None = None


def _find_rootfs_shell(rootfs: str) -> str | None:
    """Find a usable shell in the rootfs, returning its guest path.

    Symlinks are resolved within the rootfs namespace (Alpine's
    ``/bin/sh → /bin/busybox``), and a shell only visible via a bind-mounted
    host ``$PREFIX`` is rejected — the chroot could not exec it.
    """
    rootfs_real = os.path.realpath(rootfs)
    for guest_path in ("/bin/sh", f"{TERMUX_PREFIX}/bin/sh", f"{TERMUX_PREFIX}/bin/bash"):
        sh_path = os.path.join(rootfs, guest_path.lstrip("/"))
        # Fast path: regular file, no symlink resolution needed.
        if os.path.isfile(sh_path) and not os.path.islink(sh_path):
            return guest_path
        try:
            resolved = resolve_rootfs_path(rootfs, guest_path)
        except OSError:
            continue
        # Accept only a real file inside the rootfs.
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
    """Build the argv for the GNU chroot command.

    When *workdir* is set the inner command is wrapped with
    ``sh -c 'cd <dir> && exec …'`` so the chdir happens inside the chroot
    (GNU chroot's ``--skip-chdir`` only works for NEWROOT=/). Images without
    a shell skip the wrapper and run from ``/``.
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
        group_str = ",".join(str(g) for g in groups)
        args.append(f"--groups={group_str}")

    # 3. Rootfs target directory
    args.append(rootfs)

    # 4. Inner command — optionally prefixed with a cd into workdir. A `run`
    # command (image Entrypoint/Cmd) is never shell-wrapped: the image may
    # have no usable in-rootfs shell.
    cmd = list(inner_cmd) if inner_cmd else []
    if workdir and workdir != "/" and not is_run:
        shell_path = _find_rootfs_shell(rootfs)
        if shell_path:
            # cd inside the chroot, falling back to /; exec keeps the PID
            # tree clean.
            quoted_workdir = shlex.quote(workdir)
            wrapped = (
                f"cd {quoted_workdir} 2>/dev/null || cd /; exec {shlex.join(cmd)}"
                if cmd
                else f"cd {quoted_workdir} 2>/dev/null || cd /"
            )
            args.extend([shell_path, "-c", wrapped])
        else:
            # No shell to wrap with; run directly from /.
            log.debug(
                "No usable shell in rootfs %s; skipping workdir cd to %s",
                rootfs,
                workdir,
            )
            args.extend(cmd)
    else:
        args.extend(cmd)

    return args


def format_get_chroot_cmd(child_env: dict, exec_argv: list[str]) -> str:
    """Format the argv for --get-chroot-cmd as a copy-pasteable command.

    Carries its own root elevation: ``sudo`` where it exists, else Android's
    raw ``su -c`` on Termux.
    """
    parts = ["env", "-i"]
    parts.extend(f"{k}={shlex.quote(v)}" for k, v in child_env.items())
    parts.extend(shlex.quote(a) for a in exec_argv)
    body = " \\\n  ".join(parts)
    if IS_TERMUX and not shutil.which("sudo"):
        from chroot_distro.elevate import _find_termux_su

        return f"{_find_termux_su() or 'su'} -c {shlex.quote(body)}"
    return f"sudo {body}"


def build_chroot_config(
    rootfs: str,
    login_uid: str | None = None,
    login_gid: str | None = None,
    groups: list[str] | None = None,
    workdir: str = "",
    inner_cmd: list[str] | None = None,
    is_run: bool = False,
) -> ChrootConfig:
    """Build a :class:`ChrootConfig` for native chroot execution; the
    signature mirrors :func:`build_chroot_args`."""
    uid: int | None = None
    gid: int | None = None
    parsed_groups: list[int] | None = None

    if login_uid is not None:
        with contextlib.suppress(ValueError, TypeError):
            uid = int(login_uid)

    if login_gid is not None:
        with contextlib.suppress(ValueError, TypeError):
            gid = int(login_gid)

    if groups:
        parsed_groups = []
        for g in groups:
            with contextlib.suppress(ValueError, TypeError):
                parsed_groups.append(int(g))

    # Workdir wrapping, same logic as build_chroot_args.
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
