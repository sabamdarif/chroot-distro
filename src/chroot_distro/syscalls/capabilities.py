"""Capability bounding set management for container isolation.

When user namespace isolation is NOT available (container root = host root),
we drop dangerous capabilities from the bounding set to limit damage.

Users who need full capabilities (e.g. for specific privileged programs)
can opt out with the ``CD_NO_CAP_DROP=1`` environment variable.
"""

from __future__ import annotations

import logging
import os

from chroot_distro.syscalls._constants import (
    CAP_MAC_ADMIN,
    CAP_MAC_OVERRIDE,
    CAP_SYS_BOOT,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_RAWIO,
    PR_CAPBSET_DROP,
)
from chroot_distro.syscalls._libc import libc_prctl

log = logging.getLogger(__name__)

# Capabilities to DROP from the bounding set when no user namespace.
#
# Intentionally NOT dropping:
#   CAP_SYS_ADMIN  -- needed for mount(2) inside the container
#   CAP_SYS_CHROOT -- needed for chroot(2)
#   CAP_SETUID/CAP_SETGID -- needed for user switching
#   CAP_MKNOD -- needed for /dev node creation
#   CAP_DAC_OVERRIDE -- needed for file access inside rootfs
CAPS_TO_DROP: tuple[int, ...] = (
    CAP_SYS_MODULE,  # Load/unload kernel modules on host
    CAP_SYS_RAWIO,  # Raw I/O port access to host devices
    CAP_SYS_PTRACE,  # Attach to arbitrary host processes
    CAP_SYS_BOOT,  # Reboot/kexec the host
    CAP_MAC_OVERRIDE,  # Override MAC (SELinux/AppArmor) restrictions
    CAP_MAC_ADMIN,  # Tamper with MAC policy
)

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Human-readable names for log messages.
_CAP_NAMES: dict[int, str] = {
    CAP_SYS_MODULE: "CAP_SYS_MODULE",
    CAP_SYS_RAWIO: "CAP_SYS_RAWIO",
    CAP_SYS_PTRACE: "CAP_SYS_PTRACE",
    CAP_SYS_BOOT: "CAP_SYS_BOOT",
    CAP_MAC_OVERRIDE: "CAP_MAC_OVERRIDE",
    CAP_MAC_ADMIN: "CAP_MAC_ADMIN",
}


def should_drop_caps() -> bool:
    """Return True unless the user opted out via ``CD_NO_CAP_DROP=1``."""
    return os.environ.get("CD_NO_CAP_DROP", "").strip().lower() not in _TRUTHY


def drop_bounding_caps(
    caps: tuple[int, ...] = CAPS_TO_DROP,
) -> list[str]:
    """Drop dangerous capabilities from the bounding set.

    Best-effort: individual cap drops that fail are logged and returned
    as warning strings, but do not prevent container startup.

    Returns:
        A list of human-readable warnings for caps that could not be
        dropped (empty list on full success).
    """
    warnings: list[str] = []

    if not should_drop_caps():
        log.debug("Capability drop disabled via CD_NO_CAP_DROP=1")
        return warnings

    for cap in caps:
        cap_name = _CAP_NAMES.get(cap, f"cap_{cap}")
        try:
            result = libc_prctl(PR_CAPBSET_DROP, cap)
            if result < 0:
                msg = f"Failed to drop {cap_name} from bounding set"
                log.debug(msg)
                warnings.append(msg)
            else:
                log.debug("Dropped %s from bounding set", cap_name)
        except OSError as exc:
            msg = f"prctl(PR_CAPBSET_DROP, {cap_name}) failed: {exc}"
            log.debug(msg)
            warnings.append(msg)

    return warnings
