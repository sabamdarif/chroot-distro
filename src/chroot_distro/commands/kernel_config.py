# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Which kernel features this host has, for the `info` report.

Every answer comes from the running kernel, never from its build config. A
`CONFIG_*` line is a claim about how a kernel was compiled, vendor kernels
contradict their own, and Android ships no config at all, so the question asked
here is the one that decides whether a feature works: is the interface there, and
does the call succeed. Namespaces are proved by creating one in a throw-away
child, filesystems by `/proc/filesystems` and then the mount point itself, and the
devpts question by mounting a scratch instance.

Only the features this program uses are checked, grouped by the feature each one
powers, and the report is advisory: a missing required feature explains why
`--isolated` degraded, a missing optional one affects an extra. A key that maps to
no probe answers `unknown` rather than guessing, and an unreadable
`/proc/filesystems` stays distinct from a readable one that lacks the type, so
"cannot tell" is never reported as "absent".

`probe_devpts_multi_instance` is the one probe that acts: below 4.7 it mounts a
scratch `newinstance` devpts and looks for host ptys, because vendor kernels
disagree about that option and the mount is the authority. It needs root,
unmounts and removes the scratch directory in a `finally`, and goes through the
`syscalls` wrappers like everything else.
"""

import contextlib
import errno
import functools
import os
import platform
import re
import tempfile
from dataclasses import dataclass

from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
)
from chroot_distro.syscalls.unshare import probe_namespace_support

# Probe outcome, the only vocabulary the report needs.
#   "present" -> the feature works on this kernel, right now
#   "absent"  -> it does not work here
#   "unknown" -> the probe could not decide
PROBE_PRESENT = "present"
PROBE_ABSENT = "absent"
PROBE_UNKNOWN = "unknown"

# /proc/self/ns entry name -> the flag that creates it. The kernel names a
# namespace by that file, so a probe key is the kernel's own name for it.
NAMESPACE_PROBES: dict[str, int] = {
    "mnt": CLONE_NEWNS,
    "pid": CLONE_NEWPID,
    "uts": CLONE_NEWUTS,
    "ipc": CLONE_NEWIPC,
    "user": CLONE_NEWUSER,
    "cgroup": CLONE_NEWCGROUP,
}

# Filesystem type -> a path whose mount proves it is usable, or None when no
# fixed path does (the type in /proc/filesystems is then the whole answer).
FILESYSTEM_PROBES: dict[str, str | None] = {
    "proc": "/proc",
    "sysfs": "/sys",
    "tmpfs": None,
    "devtmpfs": None,
    "devpts": "/dev/pts",
}


@dataclass(frozen=True)
class KernelFeature:
    """One kernel feature chroot-distro relies on, and how the report reads it."""

    key: str  # a namespace name, a filesystem type, or a probe selector
    label: str  # what a user sees, e.g. "PID namespace"
    purpose: str  # what the feature is for, in one clause
    required: bool  # True if a degradation follows when it is missing


@dataclass(frozen=True)
class KernelFeatureGroup:
    """A named group of related kernel features."""

    title: str
    features: tuple[KernelFeature, ...]


KERNEL_FEATURE_GROUPS: tuple[KernelFeatureGroup, ...] = (
    KernelFeatureGroup(
        title="Namespace isolation (--isolated, CD_USE_NS=1)",
        features=(
            KernelFeature("mnt", "mount namespace", "isolation from host mounts", required=True),
            KernelFeature("pid", "PID namespace", "escape-proof /proc", required=True),
            KernelFeature("uts", "UTS namespace", "container hostname", required=True),
            KernelFeature("ipc", "IPC namespace", "SysV IPC and POSIX message queues", required=True),
            KernelFeature("user", "user namespace", "uid remapping, capability scoping", required=False),
        ),
    ),
    KernelFeatureGroup(
        title="Pseudo-filesystems (every chroot login)",
        features=(
            KernelFeature("proc", "procfs", "/proc", required=True),
            KernelFeature("sysfs", "sysfs", "/sys", required=True),
            KernelFeature("devpts", "devpts", "/dev/pts login ptys", required=True),
            KernelFeature("devpts-multi", "devpts multi-instance", "private container ptys", required=False),
            KernelFeature("devtmpfs", "devtmpfs", "/dev population", required=False),
            KernelFeature("tmpfs", "tmpfs", "fresh /dev, /dev/shm", required=False),
        ),
    ),
    KernelFeatureGroup(
        title="Cgroups",
        features=(
            KernelFeature("cgroup-fs", "cgroup filesystem", "cgroup hierarchy under /sys/fs/cgroup", required=False),
            KernelFeature("cgroup", "cgroup namespace", "container sees its own cgroup root", required=False),
        ),
    ),
)


def kernel_version_tuple() -> tuple[int, int]:
    """Return (major, minor) of the running kernel, or (0, 0) when unknown."""
    try:
        release = os.uname().release
    except (OSError, AttributeError):
        release = platform.release()
    match = re.match(r"(\d+)\.(\d+)", release)
    if not match:
        return (0, 0)
    return int(match.group(1)), int(match.group(2))


def probe_devpts_multi_instance() -> str:
    """Whether each devpts mount is its own instance.

    >= 4.7 always is (the option was removed in 4.9). Older kernels: mount a
    scratch 'newinstance' devpts; empty means per-mount instances, host ptys
    visible means the single shared instance. Vendor kernels disagree with
    themselves, so the mount probe is the authority. Needs root, else
    PROBE_UNKNOWN.
    """
    if kernel_version_tuple() >= (4, 7):
        return PROBE_PRESENT
    if os.getuid() != 0:
        return PROBE_UNKNOWN

    from chroot_distro.syscalls.mount import native_mount
    from chroot_distro.syscalls.umount import native_umount

    scratch = tempfile.mkdtemp(prefix="cd-devpts-probe-")
    mounted = False
    try:
        native_mount("devpts", scratch, "devpts", 0, "newinstance,ptmxmode=0666")
        mounted = True
        entries = set(os.listdir(scratch)) - {"ptmx"}
        return PROBE_ABSENT if entries else PROBE_PRESENT
    except OSError as exc:
        # Single-instance kernels reject 'newinstance' with EINVAL.
        return PROBE_ABSENT if exc.errno == errno.EINVAL else PROBE_UNKNOWN
    finally:
        if mounted:
            with contextlib.suppress(OSError):
                native_umount(scratch)
        with contextlib.suppress(OSError):
            os.rmdir(scratch)


def _proc_filesystems() -> set[str] | None:
    """Return the filesystem types the running kernel supports, or None.

    Parsed from /proc/filesystems (last column; the first is 'nodev' for
    pseudo-filesystems). Returns None when the file cannot be read, so callers
    can distinguish 'unreadable' (unknown) from 'readable but type absent'.
    """
    types: set[str] = set()
    try:
        with open("/proc/filesystems", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                # Format is two tab-separated columns: an optional 'nodev'
                # marker and the filesystem type. The type is the last field.
                parts = raw.split()
                if parts:
                    types.add(parts[-1])
    except OSError:
        return None
    return types


def _has_fs_in_mounts(fstype: str) -> bool:
    """Return True if fstype is active in /proc/mounts."""
    try:
        for path in ("/proc/mounts", "/proc/self/mounts"):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = line.split()
                        if len(parts) >= 3 and parts[2] == fstype:
                            return True
                break
            except OSError:
                continue
    except OSError:
        pass
    return False


def _ns_dir_entries() -> set[str] | None:
    """Return the namespace names listed under /proc/self/ns, or None.

    Listing the directory is more reliable than stat-ing each entry: the ns
    files are special nodes whose stat() target can be denied to unprivileged
    callers (notably on Android), which would make os.path.exists() lie.
    """
    try:
        return set(os.listdir("/proc/self/ns"))
    except OSError:
        return None


@functools.lru_cache(maxsize=len(NAMESPACE_PROBES))
def _namespace_works(flag: int) -> bool:
    """Whether unshare(2) accepts *flag* here, tried in a throw-away child.

    Cached: the answer cannot change while this process lives, and the report
    asks about the same namespace from more than one section.
    """
    return bool(probe_namespace_support(flag) & flag)


def _probe_namespace(name: str, flag: int) -> str:
    """Prove the *name* namespace works by creating it, the way `login` will.

    The /proc/self/ns listing is a fork-free negative answer; creating the
    namespace is what decides, since a kernel can refuse a flag for the caller's
    own privileges even with the interface present. An unlistable directory is
    not an answer, so it still forks.
    """
    entries = _ns_dir_entries()
    if entries is not None and name not in entries:
        return PROBE_ABSENT
    return PROBE_PRESENT if _namespace_works(flag) else PROBE_ABSENT


def _probe_filesystem(fstype: str, mount_hint: str | None) -> str:
    """Whether *fstype* is usable now, by /proc/filesystems then its mount.

    An unreadable /proc/filesystems leaves the mount table and the mount hint as
    the only evidence, and reports PROBE_UNKNOWN when neither says anything.
    """
    fstypes = _proc_filesystems()
    if fstypes is not None and fstype in fstypes:
        return PROBE_PRESENT
    if mount_hint and os.path.isdir(mount_hint):
        return PROBE_PRESENT
    if fstypes is None:
        return PROBE_PRESENT if _has_fs_in_mounts(fstype) else PROBE_UNKNOWN
    return PROBE_ABSENT


def _probe_cgroup_fs() -> str:
    """Whether a cgroup hierarchy is there: its fstype, or a live mount."""
    fstypes = _proc_filesystems()
    has_dir = os.path.isdir("/sys/fs/cgroup")
    if fstypes is None:
        return PROBE_PRESENT if has_dir else PROBE_UNKNOWN
    if "cgroup" in fstypes or "cgroup2" in fstypes or has_dir:
        return PROBE_PRESENT
    return PROBE_ABSENT


def probe_feature(key: str) -> str:
    """Resolve one :data:`KERNEL_FEATURE_GROUPS` key to a probe outcome.

    An unlisted key is PROBE_UNKNOWN: nothing here guesses at a feature it has no
    way to test.
    """
    flag = NAMESPACE_PROBES.get(key)
    if flag is not None:
        return _probe_namespace(key, flag)
    if key in FILESYSTEM_PROBES:
        return _probe_filesystem(key, FILESYSTEM_PROBES[key])
    if key == "cgroup-fs":
        return _probe_cgroup_fs()
    if key == "devpts-multi":
        return probe_devpts_multi_instance()
    return PROBE_UNKNOWN


__all__ = (
    "FILESYSTEM_PROBES",
    "KERNEL_FEATURE_GROUPS",
    "NAMESPACE_PROBES",
    "PROBE_ABSENT",
    "PROBE_PRESENT",
    "PROBE_UNKNOWN",
    "KernelFeature",
    "KernelFeatureGroup",
    "kernel_version_tuple",
    "probe_devpts_multi_instance",
    "probe_feature",
)
