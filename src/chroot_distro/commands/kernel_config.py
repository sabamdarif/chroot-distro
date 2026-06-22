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
    "KernelFlag",
    "KernelFlagGroup",
    "find_kernel_config",
    "lookup_flag",
    "parse_kernel_config",
)
