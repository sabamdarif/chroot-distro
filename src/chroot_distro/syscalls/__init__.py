# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Pure-Python kernel access, in place of the binaries this program refuses to call.

Every submodule below reaches the kernel through ctypes and libc: chroot(1),
mount(1), umount(1), unshare(1) and nsenter(1) are reimplemented here, and nothing
new in the tree may exec a binary to reach a syscall. This file re-exports the
constants used outside the package so a caller can name `syscalls.MS_BIND` without
importing the private `_constants` module.
"""

from __future__ import annotations

from chroot_distro.syscalls._constants import (
    CAP_MAC_ADMIN,
    CAP_MAC_OVERRIDE,
    CAP_SYS_BOOT,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_RAWIO,
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWTIME,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    MNT_DETACH,
    MNT_FORCE,
    MS_BIND,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_RDONLY,
    MS_REC,
    MS_REMOUNT,
    MS_SHARED,
    MS_SLAVE,
    PR_CAPBSET_DROP,
    PR_CAPBSET_READ,
    S_IFCHR,
)

__all__ = [
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_SYS_BOOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CLONE_NEWCGROUP",
    "CLONE_NEWIPC",
    "CLONE_NEWNET",
    "CLONE_NEWNS",
    "CLONE_NEWPID",
    "CLONE_NEWTIME",
    "CLONE_NEWUSER",
    "CLONE_NEWUTS",
    "MNT_DETACH",
    "MNT_FORCE",
    "MS_BIND",
    "MS_NODEV",
    "MS_NOEXEC",
    "MS_NOSUID",
    "MS_PRIVATE",
    "MS_RDONLY",
    "MS_REC",
    "MS_REMOUNT",
    "MS_SHARED",
    "MS_SLAVE",
    "PR_CAPBSET_DROP",
    "PR_CAPBSET_READ",
    "S_IFCHR",
]
