# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The `.Xauthority` format, so X11 cookie handling needs no `xauth` binary.

X11 setup selects entries from the host file here and writes a copy owned by
the guest. LibXau's on-disk format is all that takes.

Per entry, all multi-byte integers big-endian:

    family:         uint16
    address_length: uint16
    address:        bytes[address_length]
    number_length:  uint16
    number:         bytes[number_length]   (display number as ASCII, e.g. b"0")
    name_length:    uint16
    name:           bytes[name_length]     (auth protocol, e.g. b"MIT-MAGIC-COOKIE-1")
    data_length:    uint16
    data:           bytes[data_length]     (the cookie)

A cookie file is written by the compositor or the X server, not by this program,
so a short read ends the parse rather than producing an entry: `_read_entry`
answers `None` on any truncation and `read_xauthority` keeps the valid entries
that preceded it. A cookie is a secret, so `write_xauthority` creates the file
0600 through an exclusive atomic temporary. A caller writing into a guest pins
the destination parent and supplies its descriptor; ownership is set on the
temporary before publication. Failures before publication preserve any old file.

`match_display` follows libXau: a `FAMILY_WILD` entry matches anything, a
`FAMILY_LOCAL` one matches on hostname (or an empty address, which some systems
write) plus display number, and the screen after the dot is ignored.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import socket
import struct
from typing import BinaryIO, cast

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write

log = logging.getLogger(__name__)

"""IPv4 connection."""

FAMILY_LOCAL: int = 256
"""Local / Unix-domain socket connection."""

FAMILY_WILD: int = 65535
"""Wildcard: matches any connection family."""

_UINT16 = struct.Struct("!H")


@dataclasses.dataclass(slots=True)
class XauthEntry:
    """A single entry in an ``.Xauthority`` file."""

    family: int
    """Connection family (``FAMILY_LOCAL``, ``FAMILY_WILD``, etc.)."""

    address: bytes
    """Host address (hostname bytes for local, IP bytes for network)."""

    number: bytes
    """Display number as ASCII digits (e.g. ``b"0"``)."""

    name: bytes
    """Authentication protocol name (e.g. ``b"MIT-MAGIC-COOKIE-1"``)."""

    data: bytes
    """Authentication data (the cookie)."""


def _read_uint16(fp: BinaryIO) -> int | None:
    """Read a big-endian uint16 from *fp*, returning ``None`` on EOF/truncation."""
    buf = fp.read(2)
    if len(buf) < 2:
        return None
    return int(_UINT16.unpack(buf)[0])


def _read_bytes(fp: BinaryIO, length: int) -> bytes | None:
    """Read exactly *length* bytes, returning ``None`` on truncation."""
    buf = fp.read(length)
    if len(buf) < length:
        return None
    return buf


def _read_entry(fp: BinaryIO) -> XauthEntry | None:
    """Read a single Xauthority entry from *fp*.

    Returns ``None`` on EOF or if the entry is truncated.
    """
    family = _read_uint16(fp)
    if family is None:
        return None

    address_len = _read_uint16(fp)
    if address_len is None:
        return None
    address = _read_bytes(fp, address_len)
    if address is None:
        return None

    number_len = _read_uint16(fp)
    if number_len is None:
        return None
    number = _read_bytes(fp, number_len)
    if number is None:
        return None

    name_len = _read_uint16(fp)
    if name_len is None:
        return None
    name = _read_bytes(fp, name_len)
    if name is None:
        return None

    data_len = _read_uint16(fp)
    if data_len is None:
        return None
    data = _read_bytes(fp, data_len)
    if data is None:
        return None

    return XauthEntry(family=family, address=address, number=number, name=name, data=data)


def _write_entry(fp: BinaryIO, entry: XauthEntry) -> None:
    """Serialise a single Xauthority entry to *fp*."""
    fp.write(_UINT16.pack(entry.family))
    fp.write(_UINT16.pack(len(entry.address)))
    fp.write(entry.address)
    fp.write(_UINT16.pack(len(entry.number)))
    fp.write(entry.number)
    fp.write(_UINT16.pack(len(entry.name)))
    fp.write(entry.name)
    fp.write(_UINT16.pack(len(entry.data)))
    fp.write(entry.data)


def read_xauthority(path: str | int) -> list[XauthEntry]:
    """Read all entries from an ``.Xauthority`` file at *path*.

    Returns an empty list when the file does not exist, is empty, or
    contains only corrupt/truncated data.  Valid entries preceding a
    truncated tail are still returned. An integer is an already-open file
    descriptor; this function takes ownership and closes it after reading.
    """
    entries: list[XauthEntry] = []
    try:
        with open(path, "rb") as fp:
            while True:
                entry = _read_entry(fp)
                if entry is None:
                    break
                entries.append(entry)
    except (OSError, ValueError) as exc:
        # File missing, unreadable, or garbage: return what we have.
        log.warning("Failed to read Xauthority file at %s: %s", path, exc)
    return entries


def write_xauthority(
    path: str,
    entries: list[XauthEntry],
    *,
    dir_fd: int | None = None,
    owner: tuple[int, int] | None = None,
) -> None:
    """Write *entries* to an ``.Xauthority`` file at *path*.

    The file is created with mode ``0o600`` (owner-only read/write).
    With *dir_fd*, path is a filename under the caller's pinned parent.
    Otherwise the named parent is opened once. An existing file is replaced
    atomically, with *owner* set through the temporary's descriptor first.
    """
    own_fd = None
    try:
        if dir_fd is None:
            own_fd = dir_fd = dirfd.opendir(os.path.dirname(path) or ".")
            path = os.path.basename(path)
        with atomic_write(path, binary_mode=True, mode=0o600, dir_fd=dir_fd) as fp:
            if owner is not None:
                os.fchown(fp.fileno(), *owner)
            for entry in entries:
                _write_entry(cast(BinaryIO, fp), entry)
    finally:
        if own_fd is not None:
            os.close(own_fd)


def _parse_display(display: str) -> tuple[int, bytes]:
    """Parse an X11 display string into ``(family, number_bytes)``.

    Supported forms::

        :0        →  FAMILY_LOCAL, b"0"
        :0.0      →  FAMILY_LOCAL, b"0"  (screen ignored)
        unix:0    →  FAMILY_LOCAL, b"0"
        host:0    →  FAMILY_LOCAL, b"0"  (treated as local for matching)

    The screen number (after the dot) is always stripped.
    """
    if display.startswith("unix:"):
        display = display[4:]  # keep the colon → ":0"

    colon = display.rfind(":")
    if colon == -1:
        # Malformed, so the whole string counts as display number "0".
        return FAMILY_LOCAL, b"0"

    number_part = display[colon + 1 :]
    dot = number_part.find(".")
    if dot != -1:
        number_part = number_part[:dot]

    number = number_part.encode("ascii", errors="replace") if number_part else b"0"
    return FAMILY_LOCAL, number


def match_display(entry: XauthEntry, display: str) -> bool:
    """Return ``True`` if *entry* matches the X11 *display* string.

    Matching rules (following ``xauth`` / libXau behaviour):

    * ``FAMILY_WILD`` entries match any display.
    * ``FAMILY_LOCAL`` entries match when the entry's address equals the
      local hostname (from :func:`socket.gethostname`) and the display
      number matches.
    * The screen number portion of the display string is ignored.
    """
    if entry.family == FAMILY_WILD:
        return True

    family, number = _parse_display(display)

    if entry.family == FAMILY_LOCAL and family == FAMILY_LOCAL:
        hostname = socket.gethostname().encode("ascii", errors="replace")
        if entry.address == hostname and entry.number == number:
            return True
        # Some systems write an empty address for local entries.
        if entry.address == b"" and entry.number == number:
            return True

    return False


def extract_entries(
    source_path: str,
    dest_path: str,
    display_names: list[str],
) -> bool:
    """Extract matching auth entries from *source_path* into *dest_path*.

    This is the pure-Python equivalent of::

        xauth -f <source_path> extract <dest_path> <display>

    Tries each display name in *display_names* in order and writes the
    first set of matching entries found.

    Returns ``True`` if at least one entry was written, ``False`` otherwise.
    """
    all_entries = read_xauthority(source_path)
    if not all_entries:
        return False

    for display in display_names:
        matched = [e for e in all_entries if match_display(e, display)]
        if matched:
            write_xauthority(dest_path, matched)
            return True

    return False
