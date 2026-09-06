# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Describe a chroot as data: who, where, and what to run.

A session hands `syscalls/chroot.py` a `ChrootConfig` rather than a command line,
so nothing here execs anything. `chroot_display_argv` and `format_get_chroot_cmd`
render the equivalent GNU `chroot` invocation, and both exist only for
`--get-chroot-cmd`: they are printed, never run.

`build_chroot_config` is where the one piece of real behaviour lives. A workdir is
applied by wrapping the command in `sh -c 'cd <dir>; exec ...'` instead of being
passed as a chdir, because the path has to mean what it means inside the chroot.
That needs a shell that the chroot can actually exec, so `_find_rootfs_shell`
resolves candidates within the rootfs and refuses one that is only visible through
a bind-mounted host `$PREFIX`. An image with no usable shell, and a `run` command
(the image's own Entrypoint/Cmd, which may have no shell at all), start from `/`
instead.
"""

import contextlib
import logging
import os
import shlex
import shutil
from dataclasses import dataclass, field

from chroot_distro.commands.login.passwd import resolve_rootfs_path
from chroot_distro.constants import IS_TERMUX, TERMUX_PREFIX

log = logging.getLogger(__name__)


@dataclass
class ChrootConfig:
    """Chroot invocation parameters for
    :func:`chroot_distro.syscalls.chroot.chroot_and_run`."""

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
    host ``$PREFIX`` is rejected: the chroot could not exec it.
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


def chroot_display_argv(config: ChrootConfig, ns_prefix: list[str] | None = None) -> list[str]:
    """Render *config* as the GNU ``chroot`` command line it is equivalent to.

    Only ever printed, for ``--get-chroot-cmd``: the session itself never execs
    a binary to enter the chroot. *ns_prefix* is what a shell would need in
    front of it to be in the session's namespaces first.
    """
    argv = list(ns_prefix) if ns_prefix else []
    argv.append("chroot")
    if config.uid is not None:
        userspec = str(config.uid)
        if config.gid is not None:
            userspec += f":{config.gid}"
        argv.append(f"--userspec={userspec}")
    if config.groups:
        argv.append("--groups=" + ",".join(str(g) for g in config.groups))
    argv.append(config.rootfs)
    argv.extend(config.command)
    return argv


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
    """Build a :class:`ChrootConfig` for native chroot execution.

    When *workdir* is set the inner command is wrapped with
    ``sh -c 'cd <dir> && exec ...'`` so the chdir happens inside the chroot,
    where the path means what the Dockerfile or the user meant by it. Images
    without a shell run from ``/``, and a ``run`` command (image
    Entrypoint/Cmd) is never wrapped: the image may have no usable shell.
    """
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
