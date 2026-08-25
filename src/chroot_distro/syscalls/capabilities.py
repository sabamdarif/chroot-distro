# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Drop the capabilities a container has no business holding.

Without a user namespace, container root *is* host root, so the bounding set is the
only thing left between a guest process and the host. `CAPS_TO_DROP` names what
goes: loading kernel modules, raw I/O, ptrace of arbitrary host processes, reboot
and kexec, and overriding or editing MAC policy. What stays is what a container
genuinely needs, CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SETUID, CAP_SETGID, CAP_MKNOD
and CAP_DAC_OVERRIDE, which is why this is a mitigation and not a sandbox: a user
namespace is the real boundary, and this is the fallback when none is available.

PR_CAPBSET_DROP is irreversible for the process and everything it forks, so the
drop belongs immediately before the exec and after any privileged setup the caller
still has to do. A failed drop is a warning string, not an exception: a container
that will not start is worse than one running with a capability the kernel refused
to remove. `CD_NO_CAP_DROP=1` skips the whole thing, for a guest program that needs
the full set.
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
#   CAP_SYS_ADMIN: mount(2) inside the container
#   CAP_SYS_CHROOT: chroot(2)
#   CAP_SETUID/CAP_SETGID: user switching
#   CAP_MKNOD: /dev node creation
#   CAP_DAC_OVERRIDE: file access inside the rootfs
CAPS_TO_DROP: tuple[int, ...] = (
    CAP_SYS_MODULE,  # Load/unload kernel modules on host
    CAP_SYS_RAWIO,  # Raw I/O port access to host devices
    CAP_SYS_PTRACE,  # Attach to arbitrary host processes
    CAP_SYS_BOOT,  # Reboot/kexec the host
    CAP_MAC_OVERRIDE,  # Override MAC (SELinux/AppArmor) restrictions
    CAP_MAC_ADMIN,  # Tamper with MAC policy
)

_TRUTHY = frozenset({"1", "true", "yes", "on"})

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
