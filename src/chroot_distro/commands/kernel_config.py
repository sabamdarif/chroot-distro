"""Kernel build-config inspection for the `info` command.

Reads the running kernel's build configuration (``CONFIG_*`` options) and
reports which of the features chroot-distro relies on are compiled in. The
config-file discovery mirrors the approach used by the bundled
``check-config.sh`` (and lxc-checkconfig): ``/proc/config.gz`` first, then the
usual ``/boot`` / ``/usr/src`` fallbacks.

Only the options chroot-distro actually uses are checked, grouped by the
feature each one powers:

* Namespace isolation (``--isolated`` and ``CD_USE_NS=1``): the mount/PID/UTS/
  IPC namespaces plus the umbrella ``CONFIG_NAMESPACES``.
* Pseudo-filesystems that every chroot login mounts (procfs, sysfs, devpts,
  devtmpfs/tmpfs for the fresh ``/dev`` under maximum isolation).
* Cgroups, used for the Docker-on-Android integration.

The result is intentionally advisory: a missing *required* option explains why
``--isolated`` / ``CD_USE_NS`` degrade on that kernel, while missing optional
options only affect specific extras (e.g. Docker).
"""

import gzip
import os
import platform
import re
from dataclasses import dataclass

# Runtime-probe outcome, distinct from the static-config states above.
#   "present" -> the feature is available right now on this running kernel
#   "absent"  -> the feature is not available
#   "unknown" -> could not be determined by probing
PROBE_PRESENT = "present"
PROBE_ABSENT = "absent"
PROBE_UNKNOWN = "unknown"

# Outcome of a single CONFIG_* lookup.
#   "y"       -> built in (``=y``)
#   "m"       -> built as a loadable module (``=m``)
#   "n"       -> explicitly disabled / not set
#   "unknown" -> the kernel config could not be read at all
CONFIG_BUILTIN = "y"
CONFIG_MODULE = "m"
CONFIG_MISSING = "n"
CONFIG_UNKNOWN = "unknown"


@dataclass(frozen=True)
class KernelFlag:
    """A kernel option chroot-distro checks for, and why it matters."""

    name: str  # without the CONFIG_ prefix, e.g. "PID_NS"
    purpose: str  # short human description shown in the report
    required: bool  # True if isolation cannot work without it


@dataclass(frozen=True)
class KernelFlagGroup:
    """A named group of related kernel options."""

    title: str
    flags: tuple[KernelFlag, ...]


# Options grouped by the chroot-distro feature they enable. Names are the
# CONFIG_ suffix only; the CONFIG_ prefix is added when rendering.
KERNEL_FLAG_GROUPS: tuple[KernelFlagGroup, ...] = (
    KernelFlagGroup(
        title="Namespace isolation (--isolated, CD_USE_NS=1)",
        flags=(
            KernelFlag("NAMESPACES", "namespace support (umbrella)", required=True),
            KernelFlag("PID_NS", "PID namespace (escape-proof /proc)", required=True),
            KernelFlag("UTS_NS", "UTS namespace (container hostname)", required=True),
            KernelFlag("IPC_NS", "IPC namespace", required=True),
            KernelFlag("USER_NS", "user namespace (rootless extras)", required=False),
            KernelFlag("NET_NS", "network namespace (not yet used)", required=False),
        ),
    ),
    KernelFlagGroup(
        title="Pseudo-filesystems (every chroot login)",
        flags=(
            KernelFlag("PROC_FS", "procfs (/proc)", required=True),
            KernelFlag("SYSFS", "sysfs (/sys)", required=True),
            KernelFlag("UNIX98_PTYS", "devpts (/dev/pts login ptys)", required=True),
            KernelFlag("DEVTMPFS", "devtmpfs (/dev population)", required=False),
            KernelFlag("TMPFS", "tmpfs (fresh /dev, /dev/shm)", required=False),
        ),
    ),
    KernelFlagGroup(
        title="Cgroups (Docker-on-Android integration)",
        flags=(
            KernelFlag("CGROUPS", "cgroup support (umbrella)", required=False),
            KernelFlag("CGROUP_DEVICE", "device access control", required=False),
            KernelFlag("MEMCG", "memory controller", required=False),
            KernelFlag("CGROUP_PIDS", "pids controller", required=False),
        ),
    ),
)

# Config file locations to try, in order. Mirrors check-config.sh.
_CANDIDATE_PATHS = (
    "/proc/config.gz",
    "/boot/config-{release}",
    "/usr/src/linux-{release}/.config",
    "/usr/src/linux/.config",
)

_LINE_RE = re.compile(r"^CONFIG_([A-Z0-9_]+)=([ymn])\b")
_NOT_SET_RE = re.compile(r"^# CONFIG_([A-Z0-9_]+) is not set\b")


def _candidate_config_paths() -> list[str]:
    release = platform.release()
    return [p.format(release=release) for p in _CANDIDATE_PATHS]


def _read_config_text(path: str) -> str | None:
    """Return the decoded kernel config text at *path*, or None on failure.

    Handles the gzipped ``/proc/config.gz`` transparently.
    """
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, EOFError, gzip.BadGzipFile):
        return None


def find_kernel_config() -> tuple[str | None, str | None]:
    """Locate and read the kernel build config.

    Returns ``(path, text)``; both are None when no config could be read
    (common on locked-down Android kernels that ship no ``/proc/config.gz``).
    """
    # Allow an explicit override, matching check-config.sh's CONFIG env var.
    override = os.environ.get("CONFIG")
    candidates = ([override] if override else []) + _candidate_config_paths()
    for path in candidates:
        if not path or not os.path.exists(path):
            continue
        text = _read_config_text(path)
        if text is not None:
            return path, text
    return None, None


def _proc_filesystems() -> set[str]:
    """Return the filesystem types the running kernel supports.

    Parsed from /proc/filesystems (second column; the first is 'nodev' for
    pseudo-filesystems). Empty set if it cannot be read.
    """
    types: set[str] = set()
    try:
        with open("/proc/filesystems", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                parts = raw.split()
                if parts:
                    types.add(parts[-1])
    except OSError:
        pass
    return types


def _ns_file_present(name: str) -> bool:
    """Return True if this process exposes /proc/self/ns/<name>."""
    return os.path.exists(f"/proc/self/ns/{name}")


def _userns_present() -> bool | None:
    """Return True/False if user-namespace support is known, else None."""
    try:
        with open("/proc/sys/user/max_user_namespaces", encoding="utf-8") as fh:
            return int(fh.read().strip()) > 0
    except (OSError, ValueError):
        return _ns_file_present("user") or None


def probe_flag_runtime(name: str) -> str:
    """Best-effort live check that CONFIG_*name* is effective right now.

    Used as a fallback when the static kernel config cannot be read (e.g. the
    root-only /proc/config.gz on Android, with `info` running rootless).
    Returns PROBE_PRESENT / PROBE_ABSENT / PROBE_UNKNOWN. Only the options
    chroot-distro cares about are mapped; anything else returns PROBE_UNKNOWN
    so the caller renders it as 'unknown' rather than guessing.
    """
    # Namespaces: the umbrella is present if any ns file exists; each specific
    # namespace maps to its /proc/self/ns/<name> entry.
    ns_map = {
        "NAMESPACES": ("mnt", "pid", "uts", "ipc"),
        "PID_NS": ("pid",),
        "UTS_NS": ("uts",),
        "IPC_NS": ("ipc",),
        "NET_NS": ("net",),
    }
    if name in ns_map:
        files = ns_map[name]
        present = any(_ns_file_present(f) for f in files)
        return PROBE_PRESENT if present else PROBE_ABSENT
    if name == "USER_NS":
        res = _userns_present()
        if res is None:
            return PROBE_UNKNOWN
        return PROBE_PRESENT if res else PROBE_ABSENT

    # Pseudo-filesystems: look them up in /proc/filesystems.
    fs_map = {
        "PROC_FS": "proc",
        "SYSFS": "sysfs",
        "TMPFS": "tmpfs",
        "DEVTMPFS": "devtmpfs",
        "UNIX98_PTYS": "devpts",
    }
    if name in fs_map:
        fstypes = _proc_filesystems()
        if not fstypes:
            return PROBE_UNKNOWN
        return PROBE_PRESENT if fs_map[name] in fstypes else PROBE_ABSENT

    # Cgroups: presence of the cgroup/cgroup2 filesystem and the mount point.
    if name == "CGROUPS":
        fstypes = _proc_filesystems()
        if not fstypes:
            return PROBE_UNKNOWN
        has_cg = ("cgroup" in fstypes) or ("cgroup2" in fstypes) or os.path.isdir("/sys/fs/cgroup")
        return PROBE_PRESENT if has_cg else PROBE_ABSENT
    if name in ("CGROUP_DEVICE", "MEMCG", "CGROUP_PIDS"):
        # Specific cgroup controllers can't be reliably enumerated rootlessly
        # across cgroup v1/v2 layouts on Android, so leave them as unknown
        # rather than risk a misleading 'missing'.
        return PROBE_UNKNOWN

    return PROBE_UNKNOWN


def parse_kernel_config(text: str) -> dict[str, str]:
    """Parse kernel config *text* into ``{NAME: 'y'|'m'|'n'}``.

    NAME is the CONFIG_ suffix. Both ``CONFIG_X=y/m/n`` and the
    ``# CONFIG_X is not set`` form are recognised.
    """
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _LINE_RE.match(line)
        if match:
            result[match.group(1)] = match.group(2)
            continue
        not_set = _NOT_SET_RE.match(line)
        if not_set:
            result[not_set.group(1)] = CONFIG_MISSING
    return result


def lookup_flag(parsed: dict[str, str] | None, name: str) -> str:
    """Return the status of CONFIG_*name* given a parsed config.

    Returns CONFIG_UNKNOWN when the config itself is unavailable, otherwise
    one of CONFIG_BUILTIN / CONFIG_MODULE / CONFIG_MISSING. An option absent
    from a readable config is treated as missing.
    """
    if parsed is None:
        return CONFIG_UNKNOWN
    return parsed.get(name, CONFIG_MISSING)


__all__ = (
    "CONFIG_BUILTIN",
    "CONFIG_MISSING",
    "CONFIG_MODULE",
    "CONFIG_UNKNOWN",
    "KERNEL_FLAG_GROUPS",
    "PROBE_ABSENT",
    "PROBE_PRESENT",
    "PROBE_UNKNOWN",
    "KernelFlag",
    "KernelFlagGroup",
    "find_kernel_config",
    "lookup_flag",
    "parse_kernel_config",
    "probe_flag_runtime",
)
