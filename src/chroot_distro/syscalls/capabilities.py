# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Drop the capabilities a container has no business holding.

Without a user namespace, container root *is* host root, so the bounding set is
the only thing left between a guest process and the host. What goes is decided
by an allowlist: every capability in the kernel's range (`cap_last_cap`, read
from /proc rather than assumed) that `CAPS_TO_KEEP` does not name is dropped,
so a capability a future kernel gains is confined by default. `CAP_SYS_ADMIN`
is deliberately kept, because a distro-in-a-chroot is a lightweight machine:
mount, FUSE mounts (AppImages, sshfs) and a full guest init all want it, and
Tier C, where this runs, is common on Termux. The price of that is the device
hole `CAP_MKNOD`'s drop exists to close, and the re-chroot escape
`CAP_SYS_CHROOT`'s drop closes: neither comes back without an escape hatch.

PR_CAPBSET_DROP is irreversible for the process and everything it forks, so the
drop belongs immediately before the exec and after any privileged setup the caller
still has to do. The ambient set is cleared right after: a capability surviving
there would ride the exec into the guest. A failed drop is a warning string, not
an exception: a container that will not start is worse than one running with a
capability the kernel refused to remove. `CD_NO_CAP_DROP=1` skips the whole
thing, for a guest program that needs the full set.
"""

from __future__ import annotations

import logging
import os

from chroot_distro.syscalls._constants import (
    CAP_AUDIT_WRITE,
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_NET_BIND_SERVICE,
    CAP_NET_RAW,
    CAP_SETFCAP,
    CAP_SETGID,
    CAP_SETPCAP,
    CAP_SETUID,
    CAP_SYS_ADMIN,
    PR_CAP_AMBIENT,
    PR_CAP_AMBIENT_CLEAR_ALL,
    PR_CAPBSET_DROP,
)
from chroot_distro.syscalls._libc import libc_prctl

log = logging.getLogger(__name__)

# Capabilities the guest KEEPS when no user namespace scopes them: moby's
# default set, minus SYS_CHROOT (a chroot-only tool must not hand the guest
# the cap that escapes a chroot), plus SYS_ADMIN (mount and FUSE in guest).
CAPS_TO_KEEP: tuple[int, ...] = (
    CAP_CHOWN,  # chown on its own files
    CAP_DAC_OVERRIDE,  # file access inside the rootfs
    CAP_FOWNER,  # permission checks on files it owns
    CAP_FSETID,  # setgid bit handling
    CAP_KILL,  # signal its own processes
    CAP_SETGID,  # user switching
    CAP_SETUID,  # user switching
    CAP_SETPCAP,  # capability transfer within the permitted set
    CAP_NET_BIND_SERVICE,  # bind < 1024: sshd, httpd
    CAP_NET_RAW,  # ping, traceroute
    CAP_AUDIT_WRITE,  # login(1) and friends write audit records
    CAP_SETFCAP,  # setcap on guest binaries
    CAP_SYS_ADMIN,  # mount, FUSE, a full guest init
)

# Floor for the kernel's last capability number when /proc is unavailable.
# Dropped-by-default only works if the range is read, so this is the minimum,
# not the answer.
_FALLBACK_CAP_LAST_CAP = 40

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Names for readable logs; a capability the table does not know logs by number.
_CAP_NAMES: dict[int, str] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    10: "CAP_NET_BIND_SERVICE",
    13: "CAP_NET_RAW",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    27: "CAP_MKNOD",
    29: "CAP_AUDIT_WRITE",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
}


def should_drop_caps() -> bool:
    """Return True unless the user opted out via ``CD_NO_CAP_DROP=1``."""
    return os.environ.get("CD_NO_CAP_DROP", "").strip().lower() not in _TRUTHY


def cap_last_cap() -> int:
    """Return the kernel's highest capability number.

    Read from ``/proc/sys/kernel/cap_last_cap`` so a future kernel's new
    capabilities are covered by the drop loop; the constant is the floor when
    /proc is not visible.
    """
    try:
        with open("/proc/sys/kernel/cap_last_cap") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return _FALLBACK_CAP_LAST_CAP


def caps_to_drop() -> tuple[int, ...]:
    """Return every capability the kernel has that the keep set does not name."""
    keep = frozenset(CAPS_TO_KEEP)
    return tuple(cap for cap in range(cap_last_cap() + 1) if cap not in keep)


def drop_bounding_caps(
    caps: tuple[int, ...] | None = None,
) -> list[str]:
    """Drop every capability not in the allowlist from the bounding set.

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

    for cap in caps if caps is not None else caps_to_drop():
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


def clear_ambient_caps() -> None:
    """Clear the ambient capability set so nothing rides the exec into the guest.

    Runs after the bounding-set drop (an ambient cap needs a matching permitted
    cap, but ordering it last is the belt to that braces). Best-effort: a
    kernel without ambient support (pre-4.3, some Android) keeps working.
    """
    try:
        libc_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    except OSError as exc:
        log.debug("ambient capability clear unavailable: %s", exc)
