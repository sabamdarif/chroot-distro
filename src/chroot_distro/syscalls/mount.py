"""High-level wrappers around the Linux ``mount(2)`` syscall.

This module provides ergonomic Python functions for the most common mount
operations used when setting up a chroot environment:

* **bind mounts** — mirroring a host directory into the chroot
* **filesystem mounts** — mounting pseudo-filesystems (proc, sysfs, …)
* **propagation changes** — isolating mount events between namespaces

All functions accept native Python strings and handle encoding internally
before delegating to :func:`chroot_distro.syscalls._libc.libc_mount`.
"""

from __future__ import annotations

from chroot_distro.syscalls._constants import (
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
)
from chroot_distro.syscalls._libc import libc_mount

# Re-export propagation constants so callers can do
#   from chroot_distro.syscalls.mount import MS_PRIVATE
# without touching _constants directly.
__all__ = [
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
    "bind_mount",
    "mount_filesystem",
    "native_mount",
    "set_propagation",
]

# ---------------------------------------------------------------------------
# Option-string → flag-bit mapping (used by _parse_mount_options)
# ---------------------------------------------------------------------------

_OPTION_FLAG_MAP: dict[str, int] = {
    "ro": MS_RDONLY,
    "nosuid": MS_NOSUID,
    "nodev": MS_NODEV,
    "noexec": MS_NOEXEC,
    "remount": MS_REMOUNT,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _encode(value: str | None) -> bytes | None:
    """Encode a string to UTF-8 bytes, passing ``None`` through unchanged."""
    return value.encode() if value is not None else None


def _parse_mount_options(options: str) -> int:
    """Parse a comma-separated mount option string into a flag bitmask.

    Recognised options are mapped to their ``MS_*`` constants:

    =========  ============
    Option     Constant
    =========  ============
    ``ro``     ``MS_RDONLY``
    ``nosuid`` ``MS_NOSUID``
    ``nodev``  ``MS_NODEV``
    ``noexec`` ``MS_NOEXEC``
    ``remount````MS_REMOUNT``
    =========  ============

    Unknown options (e.g. ``"size=64m"``) are silently ignored — they
    belong in the *data* argument of ``mount(2)``, not the *flags*.

    Args:
        options: Comma-separated option string, e.g. ``"ro,nosuid,noexec"``.
            An empty string produces a bitmask of ``0``.

    Returns:
        Combined ``MS_*`` bitmask for all recognised options.
    """
    if not options:
        return 0

    flags = 0
    for raw_token in options.split(","):
        token = raw_token.strip()
        bit = _OPTION_FLAG_MAP.get(token)
        if bit is not None:
            flags |= bit
    return flags


def _parse_and_split_mount_options(options: str, initial_flags: int = 0) -> tuple[int, str]:
    """Parse comma-separated mount options.

    Generic VFS options are parsed into flags, while unknown or filesystem-specific
    options are kept as a comma-separated string for filesystem-specific data.

    Returns:
        A tuple of (combined_MS_flags, filesystem_specific_options_string).
    """
    if not options:
        return initial_flags, ""

    flags = initial_flags
    data_tokens = []
    for raw_token in options.split(","):
        token = raw_token.strip()
        bit = _OPTION_FLAG_MAP.get(token)
        if bit is not None:
            flags |= bit
        else:
            data_tokens.append(token)
    return flags, ",".join(data_tokens)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def native_mount(
    source: str | None,
    target: str,
    fstype: str | None = None,
    flags: int = 0,
    data: str | None = None,
) -> None:
    """Perform a low-level ``mount(2)`` syscall.

    This is the thinnest wrapper around :func:`libc_mount`: it encodes
    Python strings to bytes and forwards the call.  Prefer the
    higher-level helpers (:func:`bind_mount`, :func:`mount_filesystem`,
    :func:`set_propagation`) unless you need full control over every
    argument.

    Args:
        source: Source device or directory path (may be ``None`` for
            pseudo-filesystems or propagation changes).
        target: Mount-point path.
        fstype: Filesystem type string (e.g. ``"proc"``, ``"tmpfs"``).
            Pass ``None`` for bind mounts or propagation changes.
        flags: ``MS_*`` flag bitmask.  Defaults to ``0``.
        data: Filesystem-specific option string (e.g. ``"mode=0755"``).
            Pass ``None`` if not needed.

    Raises:
        OSError: If the underlying ``mount(2)`` call fails.
    """
    libc_mount(
        _encode(source),
        target.encode(),
        _encode(fstype),
        flags,
        _encode(data),
    )


def bind_mount(
    source: str,
    target: str,
    *,
    recursive: bool = False,
    readonly: bool = False,
    options: str = "",
) -> None:
    """Create a bind mount from *source* to *target*.

    A bind mount makes a directory (or file) visible at a second location
    in the filesystem tree.  This is the primary mechanism used to expose
    host paths inside a chroot.

    Args:
        source: The existing path to bind.
        target: The mount-point where *source* will appear.
        recursive: If ``True``, all sub-mounts under *source* are also
            replicated (``MS_REC``).
        readonly: Convenience flag — equivalent to passing ``"ro"`` in
            *options*.
        options: Comma-separated mount options applied via a remount
            after the initial bind.  Recognised tokens: ``ro``,
            ``nosuid``, ``nodev``, ``noexec``.  Unknown tokens are
            silently ignored.

    Raises:
        OSError: If any ``mount(2)`` call fails.

    Example:
        >>> bind_mount("/dev", "/chroot/dev", recursive=True, readonly=True)
    """
    # Step 1: initial bind mount
    bind_flags = MS_BIND
    if recursive:
        bind_flags |= MS_REC

    native_mount(source, target, None, bind_flags, None)

    # Step 2: optional remount to apply extra flags (ro, nosuid, …)
    extra_flags = _parse_mount_options(options)
    if readonly:
        extra_flags |= MS_RDONLY

    if extra_flags:
        remount_flags = MS_REMOUNT | MS_BIND | extra_flags
        if recursive:
            remount_flags |= MS_REC
        native_mount(source, target, None, remount_flags, None)


def mount_filesystem(
    source: str,
    target: str,
    fstype: str,
    *,
    flags: int = 0,
    options: str = "",
) -> None:
    """Mount a virtual or real filesystem.

    Use this for pseudo-filesystems commonly required inside a chroot:
    ``proc``, ``sysfs``, ``tmpfs``, ``devpts``, etc.

    Generic VFS options found in *options* (e.g. ``"ro"``, ``"nosuid"``,
    ``"nodev"``, ``"noexec"``) are automatically parsed and merged into the VFS
    *flags*, while filesystem-specific options are forwarded to the driver's
    *data* parameter. This avoids ``EINVAL`` failures from drivers that do
    not recognise generic options.

    Args:
        source: Source device name (often the same as *fstype* for
            pseudo-filesystems, e.g. ``"proc"``).
        target: Mount-point path.
        fstype: Filesystem type (e.g. ``"proc"``, ``"sysfs"``,
            ``"tmpfs"``, ``"devpts"``).
        flags: ``MS_*`` flag bitmask.  Defaults to ``0``.
        options: Mount options string.  Pass an empty string if not needed.

    Raises:
        OSError: If the underlying ``mount(2)`` call fails.

    Example:
        >>> mount_filesystem("proc", "/chroot/proc", "proc", flags=MS_NOSUID | MS_NODEV | MS_NOEXEC)
        >>> mount_filesystem("tmpfs", "/chroot/tmp", "tmpfs", options="size=64m,mode=1777")
    """
    parsed_flags, data = _parse_and_split_mount_options(options, flags)
    native_mount(source, target, fstype, parsed_flags, data or None)


def set_propagation(target: str, propagation: int) -> None:
    """Change mount propagation type for *target*.

    Mount propagation controls whether mount/unmount events under a
    mount-point are visible to peer or slave mounts.  This is essential
    when setting up mount namespaces for chroot isolation.

    Args:
        target: The mount-point whose propagation type to change.
        propagation: One of :data:`MS_PRIVATE`, :data:`MS_SLAVE`, or
            :data:`MS_SHARED`, optionally OR'd with :data:`MS_REC` to
            apply recursively to all sub-mounts.

    Raises:
        OSError: If the underlying ``mount(2)`` call fails.

    Example:
        >>> set_propagation("/", MS_PRIVATE | MS_REC)
    """
    native_mount("none", target, None, propagation, None)
