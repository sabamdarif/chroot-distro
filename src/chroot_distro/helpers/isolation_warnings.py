"""Human-readable isolation status warnings.

Maps each missing ``CLONE_NEW*`` flag to its security impact, likely cause,
and suggested fix.  Used by :func:`namespace.probe_and_report_namespaces` to
produce user-facing output when ``--isolated`` runs with incomplete kernel
support.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    NS_FILE_MAP,
)


@dataclass(frozen=True)
class NamespaceInfo:
    """Metadata about a single namespace type and its isolation role."""

    name: str
    flag_name: str
    kernel_config: str
    severity: str  # "critical", "high", "medium", "low"
    impacts: tuple[str, ...]
    fixes: tuple[str, ...]


NAMESPACE_INFO: dict[int, NamespaceInfo] = {
    CLONE_NEWUSER: NamespaceInfo(
        name="User namespace",
        flag_name="CLONE_NEWUSER",
        kernel_config="CONFIG_USER_NS",
        severity="critical",
        impacts=(
            "Container root has real host root capabilities",
            "Files created via sudo are owned by host uid 0",
            "Capabilities inside container apply to host kernel",
        ),
        fixes=(
            "Enable CONFIG_USER_NS in kernel config",
            "Set /proc/sys/kernel/unprivileged_userns_clone to 1",
            "Check SELinux policy allows user namespace creation",
        ),
    ),
    CLONE_NEWPID: NamespaceInfo(
        name="PID namespace",
        flag_name="CLONE_NEWPID",
        kernel_config="CONFIG_PID_NS",
        severity="high",
        impacts=(
            "Host processes visible inside container via /proc",
            "Container processes can send signals to host processes",
        ),
        fixes=("Enable CONFIG_PID_NS in kernel config",),
    ),
    CLONE_NEWUTS: NamespaceInfo(
        name="UTS namespace",
        flag_name="CLONE_NEWUTS",
        kernel_config="CONFIG_UTS_NS",
        severity="low",
        impacts=("Container shares host's hostname",),
        fixes=("Enable CONFIG_UTS_NS in kernel config",),
    ),
    CLONE_NEWIPC: NamespaceInfo(
        name="IPC namespace",
        flag_name="CLONE_NEWIPC",
        kernel_config="CONFIG_IPC_NS",
        severity="medium",
        impacts=("Container shares host SysV IPC and POSIX message queues",),
        fixes=("Enable CONFIG_IPC_NS in kernel config",),
    ),
    CLONE_NEWCGROUP: NamespaceInfo(
        name="Cgroup namespace",
        flag_name="CLONE_NEWCGROUP",
        kernel_config="CONFIG_CGROUP_NS",
        severity="low",
        impacts=("Container can see host cgroup hierarchy",),
        fixes=("Enable CONFIG_CGROUP_NS in kernel config",),
    ),
}


def format_isolation_warnings(
    missing_recommended: int,
    missing_enhancements: int,
) -> list[str]:
    """Build human-readable warning lines for missing namespaces.

    Returns a list of formatted strings suitable for printing to stderr.
    The warnings are ordered by severity (critical first).
    """
    lines: list[str] = []
    # Process in severity order: critical -> high -> medium -> low
    severity_order = ("critical", "high", "medium", "low")
    all_missing = missing_recommended | missing_enhancements

    for severity in severity_order:
        for bit, info in NAMESPACE_INFO.items():
            if not (all_missing & bit):
                continue
            if info.severity != severity:
                continue
            prefix = "\u26a0 WARNING" if severity in ("critical", "high") else "\u2139 INFO"
            lines.append(f"{prefix}: {info.name} ({info.flag_name}) not available.")
            for impact in info.impacts:
                lines.append(f"  \u2192 {impact}")
            lines.append(f"  Kernel config: {info.kernel_config}")

    return lines


def format_isolation_summary(supported: int) -> str:
    """One-line summary of active isolation.

    Example output::

        Isolation active: mount, pid, uts, ipc | Missing: user (critical), cgroup (low)
    """
    active: list[str] = []
    missing: list[str] = []

    # Check mount NS first (it has no NamespaceInfo entry -- always mandatory).
    if supported & CLONE_NEWNS:
        active.append("mount")

    for bit, info in NAMESPACE_INFO.items():
        ns_name = NS_FILE_MAP.get(bit, info.flag_name)
        if supported & bit:
            active.append(ns_name)
        else:
            missing.append(f"{ns_name} ({info.severity})")

    parts = [f"Isolation active: {', '.join(active) or 'none'}"]
    if missing:
        parts.append(f"Missing: {', '.join(missing)}")
    return " | ".join(parts)


def emit_isolation_warnings(
    missing_recommended: int,
    missing_enhancements: int,
    supported: int,
) -> None:
    """Print isolation warnings and summary to stderr."""
    lines = format_isolation_warnings(missing_recommended, missing_enhancements)
    if lines:
        sys.stderr.write("\n".join(lines) + "\n")
    summary = format_isolation_summary(supported)
    sys.stderr.write(summary + "\n")
