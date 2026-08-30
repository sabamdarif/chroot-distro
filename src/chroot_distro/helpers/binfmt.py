# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Register a binfmt_misc handler, so a foreign-arch guest can exec its own binaries.

The kernel decides how to run a foreign ELF from the entries under
`/proc/sys/fs/binfmt_misc`, and adding one is a write to `register`, so nothing
here calls `update-binfmts` or `qemu-binfmt-conf.sh`. The emulator is not run by
this program either: the kernel execs it, when the guest execs a binary whose
header matches.

Three parts of the registration are deliberate.

`F` is required, not a nicety. It makes the kernel open the interpreter at
registration time and keep that file, so the emulator does not have to exist
inside the rootfs. Without it the lookup happens at exec time in the caller's
mount namespace, which by then is the chroot, where the host's qemu is not.

`C` (take credentials from the binary) is left out. It is what makes setuid work
under emulation, and it also turns every container rootfs into a host-wide
escalation: an entry applies to every exec in the user namespace, so any local
user could run a guest's foreign setuid-root binary straight from its rootfs
path. Someone who wants that registers their own entry, and `ensure_handler`
then leaves it alone.

Coverage is answered by replaying the kernel's own match, magic and mask against
the target's ELF header, not by reading entry names: the name belongs to whoever
registered the entry and says nothing about the arch it answers for.

Since Linux 6.7 entries live on the user namespace, and a namespace without its
own binfmt_misc mount falls back to the nearest ancestor that has one. That
fallback is why `commands/login/bindings._binfmt_misc_special` must not mount a
fresh instance inside a session's user namespace: an empty instance shadows
whatever was registered here.
"""

import logging
import os
import struct

from chroot_distro.arch import ELF_MACHINE_BY_ARCH
from chroot_distro.constants import TERMUX_PREFIX
from chroot_distro.message import log_info

log = logging.getLogger(__name__)

BINFMT_DIR = "/proc/sys/fs/binfmt_misc"
_REGISTER = f"{BINFMT_DIR}/register"

# fs/binfmt_misc.c caps an interpreter path at 127 bytes.
_MAX_INTERPRETER = 127

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# EI_CLASS per arch; the e_machine half comes from arch.py, and every arch this
# program knows is little-endian, so EI_DATA is fixed at 1.
_ELF_CLASS = {"aarch64": 2, "arm": 1, "i686": 1, "riscv64": 2, "x86_64": 2}

# QEMU's own name for each user-mode emulator ("i686" is "i386" there).
_QEMU_BINARY = {
    "aarch64": "qemu-aarch64",
    "arm": "qemu-arm",
    "i686": "qemu-i386",
    "riscv64": "qemu-riscv64",
    "x86_64": "qemu-x86_64",
}

# Where a distro or Termux package drops the emulator. A static build wins: a
# dynamic one (all Termux ships) only runs when its libraries are in the guest.
_SEARCH_DIRS = (f"{TERMUX_PREFIX}/bin", "/usr/bin", "/usr/local/bin", "/bin")


def _elf_signature(arch: str) -> tuple[bytes, bytes] | None:
    """Return (magic, mask) matching the first 20 bytes of *arch*'s ELF header."""
    machine = ELF_MACHINE_BY_ARCH.get(arch)
    elf_class = _ELF_CLASS.get(arch)
    if machine is None or elf_class is None:
        return None
    # e_ident (16) then e_type=ET_EXEC and e_machine; EI_OSABI onwards is zero.
    magic = b"\x7fELF" + bytes((elf_class, 1, 1)) + bytes(9) + struct.pack("<HH", 2, machine)
    # 0xfe on e_type's low byte lets ET_DYN (a PIE) match this ET_EXEC template.
    mask = b"\xff" * 7 + b"\x00" + b"\xff" * 8 + b"\xfe\xff\xff\xff"
    return magic, mask


def _parse_entry(text: str) -> tuple[str, int, bytes, bytes] | None:
    """Return (interpreter, offset, magic, mask) for one enabled magic entry.

    None for anything this cannot judge: a disabled entry, an extension match,
    or a 'B' entry, whose interpreter a BPF program picks at exec time.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "enabled":
        return None
    interpreter = ""
    offset = 0
    magic = b""
    mask = b""
    try:
        for line in lines[1:]:
            key, _, value = line.partition(" ")
            if key == "interpreter":
                interpreter = value.strip()
            elif key == "offset":
                offset = int(value)
            elif key == "magic":
                magic = bytes.fromhex(value.strip())
            elif key == "mask":
                mask = bytes.fromhex(value.strip())
    except ValueError:
        return None
    if not interpreter or not magic or offset < 0:
        return None
    return interpreter, offset, magic, mask or b"\xff" * len(magic)


def _entry_matches(offset: int, magic: bytes, mask: bytes, header: bytes) -> bool:
    """Return True if an entry's (offset, magic, mask) would match *header*.

    An entry reaching past the 20-byte header reads as no match, so the worst
    case is registering a second entry the kernel would have matched anyway.
    """
    end = offset + len(magic)
    if end > len(header) or len(mask) < len(magic):
        return False
    chunk = header[offset:end]
    return all(c & m == g & m for c, g, m in zip(chunk, magic, mask, strict=False))


def registered_interpreter(arch: str) -> str | None:
    """Return the interpreter of an enabled entry that already answers for *arch*."""
    signature = _elf_signature(arch)
    if signature is None:
        return None
    header = signature[0]
    try:
        names = os.listdir(BINFMT_DIR)
    except OSError:
        return None
    for name in names:
        if name in ("register", "status"):
            continue
        try:
            with open(f"{BINFMT_DIR}/{name}", encoding="utf-8", errors="replace") as fh:
                parsed = _parse_entry(fh.read())
        except OSError:
            continue
        if parsed is None:
            continue
        interpreter, offset, magic, mask = parsed
        if _entry_matches(offset, magic, mask, header):
            return interpreter
    return None


def covered_arches() -> list[str]:
    """Return the foreign arches an enabled entry can already run, sorted."""
    return sorted(arch for arch in _QEMU_BINARY if registered_interpreter(arch))


def find_emulator(arch: str) -> str | None:
    """Return the path of an installed QEMU user-mode emulator for *arch*, or None."""
    name = _QEMU_BINARY.get(arch)
    if name is None:
        return None
    for candidate in (f"{name}-static", name):
        for directory in _SEARCH_DIRS:
            path = f"{directory}/{candidate}"
            if os.access(path, os.X_OK) and os.path.isfile(path):
                return path
    return None


def _escape(raw: bytes) -> str:
    r"""Return *raw* as the \xNN escapes a register line's magic and mask take."""
    return "".join(f"\\x{byte:02x}" for byte in raw)


def ensure_handler(arch: str) -> tuple[str | None, str]:
    """Give *arch* a binfmt_misc handler, registering one when nothing answers yet.

    Returns (interpreter, "") once *arch* is covered, else (None, reason). Needs
    root, and the registration outlives the session: an entry stands until it is
    removed or the host reboots, exactly like a distro's qemu-user-static.
    """
    existing = registered_interpreter(arch)
    if existing:
        return existing, ""
    if os.environ.get("CD_NO_BINFMT", "").strip().lower() in _TRUTHY:
        return None, "disabled via CD_NO_BINFMT"
    signature = _elf_signature(arch)
    if signature is None:
        return None, f"no ELF signature is known for '{arch}'"
    if not os.path.exists(_REGISTER):
        return None, "this kernel has no binfmt_misc (CONFIG_BINFMT_MISC)"
    emulator = find_emulator(arch)
    if emulator is None:
        return None, f"no QEMU user-mode emulator for '{arch}' is installed"
    if len(emulator.encode()) > _MAX_INTERPRETER or ":" in emulator:
        return None, f"the kernel cannot take '{emulator}' as an interpreter path"
    magic, mask = signature
    line = f":cd-qemu-{arch}:M:0:{_escape(magic)}:{_escape(mask)}:{emulator}:PF\n"
    try:
        with open(_REGISTER, "w", encoding="ascii") as fh:
            fh.write(line)
    except OSError as exc:
        # A concurrent session may have registered this name first.
        covered = registered_interpreter(arch)
        if covered:
            return covered, ""
        return None, f"binfmt_misc refused the registration ({exc})"
    log_info(f"Registered {emulator} as the binfmt_misc interpreter for '{arch}'.")
    return emulator, ""
