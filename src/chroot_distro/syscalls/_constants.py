"""Linux kernel constants for mount, namespace, capability, and device operations.

All values are taken from the Linux kernel headers (``<sys/mount.h>``,
``<linux/sched.h>``, ``<linux/capability.h>``) and are stable across
kernel versions.  They are architecture-independent integers.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# mount(2) flags — from <sys/mount.h>
# ---------------------------------------------------------------------------

MS_RDONLY: int = 1
"""Mount read-only."""

MS_NOSUID: int = 2
"""Ignore set-user-ID and set-group-ID bits."""

MS_NODEV: int = 4
"""Disallow access to device special files."""

MS_NOEXEC: int = 8
"""Disallow program execution."""

MS_SYNCHRONOUS: int = 16
"""Writes are synced at once."""

MS_REMOUNT: int = 32
"""Alter flags of a mounted FS."""

MS_MANDLOCK: int = 64
"""Allow mandatory locks on an FS."""

MS_DIRSYNC: int = 128
"""Directory modifications are synchronous."""

MS_NOSYMFOLLOW: int = 256
"""Do not follow symlinks."""

MS_NOATIME: int = 1024
"""Do not update access times."""

MS_NODIRATIME: int = 2048
"""Do not update directory access times."""

MS_BIND: int = 4096
"""Bind mount."""

MS_MOVE: int = 8192
"""Move an existing mount point."""

MS_REC: int = 16384
"""Recursive (used with MS_BIND and propagation flags)."""

MS_SILENT: int = 32768
"""Suppress certain kernel warning messages."""

MS_POSIXACL: int = 1 << 16
"""VFS does not apply the umask."""

MS_UNBINDABLE: int = 1 << 17
"""Make mount unbindable."""

MS_PRIVATE: int = 1 << 18
"""Make mount private (no propagation)."""

MS_SLAVE: int = 1 << 19
"""Make mount a slave (receives propagation)."""

MS_SHARED: int = 1 << 20
"""Make mount shared (propagates events)."""

MS_RELATIME: int = 1 << 21
"""Update atime relative to mtime/ctime."""

MS_KERNMOUNT: int = 1 << 22
"""Internal kernel mount."""

MS_I_VERSION: int = 1 << 23
"""Update inode I_version field."""

MS_STRICTATIME: int = 1 << 24
"""Always perform atime updates."""

MS_LAZYTIME: int = 1 << 25
"""Update the in-memory timestamps only, deferring disk writes."""

# ---------------------------------------------------------------------------
# umount2(2) flags — from <sys/mount.h>
# ---------------------------------------------------------------------------

MNT_FORCE: int = 1
"""Force unmount (abort pending requests)."""

MNT_DETACH: int = 2
"""Lazy unmount (disconnect from hierarchy, clean up when last ref drops)."""

MNT_EXPIRE: int = 4
"""Mark for expiry."""

UMOUNT_NOFOLLOW: int = 8
"""Don't follow symlinks when unmounting."""

# ---------------------------------------------------------------------------
# clone / unshare / setns namespace flags — from <linux/sched.h>
# ---------------------------------------------------------------------------

CLONE_NEWTIME: int = 0x00000080
"""New time namespace."""

CLONE_VM: int = 0x00000100
"""Share virtual memory (not used for namespaces, included for completeness)."""

CLONE_NEWNS: int = 0x00020000
"""New mount namespace."""

CLONE_NEWCGROUP: int = 0x02000000
"""New cgroup namespace."""

CLONE_NEWUTS: int = 0x04000000
"""New UTS namespace (hostname, domainname)."""

CLONE_NEWIPC: int = 0x08000000
"""New IPC namespace."""

CLONE_NEWUSER: int = 0x10000000
"""New user namespace."""

CLONE_NEWPID: int = 0x20000000
"""New PID namespace."""

CLONE_NEWNET: int = 0x40000000
"""New network namespace."""

# ---------------------------------------------------------------------------
# Mapping from CLONE_* flags to /proc/<pid>/ns/<name> filenames
# ---------------------------------------------------------------------------

NS_FILE_MAP: dict[int, str] = {
    CLONE_NEWNS: "mnt",
    CLONE_NEWUTS: "uts",
    CLONE_NEWIPC: "ipc",
    CLONE_NEWPID: "pid",
    CLONE_NEWNET: "net",
    CLONE_NEWUSER: "user",
    CLONE_NEWCGROUP: "cgroup",
    CLONE_NEWTIME: "time",
}

# Reverse map: "--mount" / "-m" → CLONE_NEWNS  (for backward compat with
# holder state files that store namespace flags as CLI-style strings).
_CLI_FLAG_TO_CLONE: dict[str, int] = {
    "--mount": CLONE_NEWNS,
    "--uts": CLONE_NEWUTS,
    "--ipc": CLONE_NEWIPC,
    "--pid": CLONE_NEWPID,
    "--net": CLONE_NEWNET,
    "--user": CLONE_NEWUSER,
    "--cgroup": CLONE_NEWCGROUP,
    # Short forms (nsenter style)
    "-m": CLONE_NEWNS,
    "-u": CLONE_NEWUTS,
    "-i": CLONE_NEWIPC,
    "-p": CLONE_NEWPID,
    "-n": CLONE_NEWNET,
    "-U": CLONE_NEWUSER,
    "-C": CLONE_NEWCGROUP,
}

# Reverse: CLONE_* → long CLI flag (for writing state files / debug output).
_CLONE_TO_CLI_FLAG: dict[int, str] = {
    CLONE_NEWNS: "--mount",
    CLONE_NEWUTS: "--uts",
    CLONE_NEWIPC: "--ipc",
    CLONE_NEWPID: "--pid",
    CLONE_NEWNET: "--net",
    CLONE_NEWUSER: "--user",
    CLONE_NEWCGROUP: "--cgroup",
}

# ---------------------------------------------------------------------------
# stat(2) mode flag for character devices — from <sys/stat.h>
# ---------------------------------------------------------------------------

S_IFCHR: int = 0o020000
"""Character device."""

# ---------------------------------------------------------------------------
# Linux capabilities — from <linux/capability.h>
# ---------------------------------------------------------------------------

CAP_DAC_OVERRIDE: int = 1
"""Override file DAC (read/write/execute) permission checks."""

CAP_DAC_READ_SEARCH: int = 2
"""Override file read permission and directory search."""

CAP_FOWNER: int = 3
"""Override ownership restrictions on file operations."""

CAP_SETGID: int = 6
"""Allow setgid(2) and supplementary group manipulation."""

CAP_SETUID: int = 7
"""Allow setuid(2)."""

CAP_SYS_CHROOT: int = 18
"""Allow chroot(2)."""

CAP_SYS_ADMIN: int = 21
"""General sysadmin capability (mount, namespaces, etc.)."""

CAP_MKNOD: int = 27
"""Allow mknod(2)."""

# ---------------------------------------------------------------------------
# prctl(2) constants — from <linux/prctl.h>
# ---------------------------------------------------------------------------

PR_SET_KEEPCAPS: int = 8
"""Keep capabilities across UID transitions."""

PR_CAP_AMBIENT: int = 47
"""Ambient capability operations."""

PR_CAP_AMBIENT_IS_SET: int = 1
"""Check if an ambient capability is set."""

PR_CAP_AMBIENT_RAISE: int = 2
"""Add a capability to the ambient set."""

PR_CAP_AMBIENT_LOWER: int = 3
"""Remove a capability from the ambient set."""

PR_CAP_AMBIENT_CLEAR_ALL: int = 4
"""Clear the entire ambient capability set."""


# ---------------------------------------------------------------------------
# Helpers for backward-compatible state file parsing
# ---------------------------------------------------------------------------


def cli_flags_to_bitmask(flags: list[str]) -> int:
    """Convert a list of CLI-style namespace flags to a CLONE_* bitmask.

    Ignores unrecognised flags (e.g. ``"--fork"``) so the caller can pass
    the raw contents of a holder state file.

    >>> cli_flags_to_bitmask(["--mount", "--pid", "--uts", "--ipc"])
    ... == CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC
    True
    """
    mask = 0
    for flag in flags:
        clone_bit = _CLI_FLAG_TO_CLONE.get(flag)
        if clone_bit is not None:
            mask |= clone_bit
    return mask


def bitmask_to_cli_flags(mask: int) -> list[str]:
    """Convert a CLONE_* bitmask to a sorted list of long CLI flags.

    >>> bitmask_to_cli_flags(CLONE_NEWNS | CLONE_NEWPID)
    ['--mount', '--pid']
    """
    return sorted(
        (flag for bit, flag in _CLONE_TO_CLI_FLAG.items() if mask & bit),
        key=lambda f: f,
    )
