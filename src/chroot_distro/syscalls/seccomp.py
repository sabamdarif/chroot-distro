# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""A seccomp denylist, installed in the guest child before the exec.

The filter is classic BPF handed to `prctl(PR_SET_SECCOMP, ...)`, no new
syscall wrapper, and it denies a fixed set a distro never touches:
`io_uring_*`, `userfaultfd`, `keyctl`, `add_key`, `request_key`, `bpf`,
`perf_event_open`, `kexec_*`, `*_module`, `acct`, `swap*`, `nfsservctl`,
`uselib`, `_sysctl`, `iopl`, `ioperm`, `open_by_handle_at`. Everything else
is allowed, so the failure mode is a program that cannot use an optional
feature (io_uring is opt-in in current PostgreSQL and Redis; `CD_NO_SECCOMP=1`
is the answer for whoever needs it) rather than a distro that cannot boot.
That is why this is a denylist and not moby's allowlist: flattening the
conditional entries of Docker's profile permits more than Docker itself,
because this project keeps `CAP_SYS_ADMIN` (a denial Docker's cap drop backs
up), and a per-arch number table of 300+ names is a silent-breakage risk a
20-entry one is not.

Two orderings are load-bearing. `keyctl` is denied, and the fresh session
keyring joins through it, so the keyring must be installed first: a keyring is
a nicety, a filter that closes kernel attack surface is not, and if the two
ever disagree the keyring loses. And the install needs privilege (or
no_new_privs, which is opt-in), so it runs before setuid while the child is
still root.

The program checks `seccomp_data.arch` first and returns ALLOW for a foreign
one: a 32-bit guest binary reports a different arch, and this project runs
those under binfmt, where the filter would otherwise kill the process on
principle rather than judge its syscalls.
"""

from __future__ import annotations

import ctypes
import logging
import os

from chroot_distro.syscalls._constants import (
    BPF_JMP_JEQ_K,
    BPF_LD_W_ABS,
    BPF_RET_K,
    PR_SET_SECCOMP,
    SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
)
from chroot_distro.syscalls._libc import libc_prctl

log = logging.getLogger(__name__)

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# seccomp_data offsets: nr at 0, arch at 4.
_SECCOMP_DATA_NR = 0
_SECCOMP_DATA_ARCH = 4

# AUDIT_ARCH_* values, from <linux/audit.h> (EM_* | 64BIT | LE bits).
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_I386 = 0x40000003
_AUDIT_ARCH_X32 = 0x4000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_AUDIT_ARCH_ARM = 0x40000028
_AUDIT_ARCH_RISCV64 = 0xC00000F3

# The arch the host's own binaries run as, plus the compat arch a 32-bit
# binary reports on the same machine. A foreign arch (a binfmt-emulated
# guest) is never seen by this program's own exec, but the compat one is.
_ARCHS_BY_HOST = {
    "x86_64": (_AUDIT_ARCH_X86_64, _AUDIT_ARCH_I386, _AUDIT_ARCH_X32),
    "i686": (_AUDIT_ARCH_I386,),
    "aarch64": (_AUDIT_ARCH_AARCH64, _AUDIT_ARCH_ARM),
    "arm": (_AUDIT_ARCH_ARM,),
    "riscv64": (_AUDIT_ARCH_RISCV64,),
}

# Which table judges a given seccomp arch value: a compat arch is judged by
# the compat numbers, since the same name has a different number there.
_ARCH_TO_TABLE = {
    _AUDIT_ARCH_X86_64: "x86_64",
    _AUDIT_ARCH_I386: "i686",
    _AUDIT_ARCH_X32: "x86_64",
    _AUDIT_ARCH_AARCH64: "aarch64",
    _AUDIT_ARCH_ARM: "arm",
    _AUDIT_ARCH_RISCV64: "riscv64",
}

# Syscall numbers per arch, from runc's vendored golang.org/x/sys zsysnum
# tables (zsysnum_linux_{amd64,arm64,386,arm,riscv64}.go). None marks a
# syscall the arch never had: it is skipped rather than mis-numbered.
_SYSCALL_NR: dict[str, dict[str, int | None]] = {
    "x86_64": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "userfaultfd": 323,
        "keyctl": 250,
        "add_key": 248,
        "request_key": 249,
        "bpf": 321,
        "perf_event_open": 298,
        "kexec_load": 246,
        "kexec_file_load": 320,
        "init_module": 175,
        "finit_module": 313,
        "delete_module": 176,
        "acct": 163,
        "swapon": 167,
        "swapoff": 168,
        "nfsservctl": 180,
        "uselib": 134,
        "_sysctl": 156,
        "iopl": 172,
        "ioperm": 173,
        "open_by_handle_at": 304,
    },
    "i686": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "userfaultfd": 374,
        "keyctl": 288,
        "add_key": 286,
        "request_key": 287,
        "bpf": 357,
        "perf_event_open": 336,
        "kexec_load": 283,
        "kexec_file_load": 320,
        "init_module": 128,
        "finit_module": 350,
        "delete_module": 129,
        "acct": 51,
        "swapon": 87,
        "swapoff": 115,
        "nfsservctl": 169,
        "uselib": 86,
        "_sysctl": 149,
        "iopl": 110,
        "ioperm": 101,
        "open_by_handle_at": 342,
    },
    "arm": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "userfaultfd": 388,
        "keyctl": 311,
        "add_key": 309,
        "request_key": 310,
        "bpf": 386,
        "perf_event_open": 364,
        "kexec_load": 347,
        "kexec_file_load": 401,
        "init_module": 128,
        "finit_module": 379,
        "delete_module": 129,
        "acct": 51,
        "swapon": 87,
        "swapoff": 115,
        "nfsservctl": 169,
        "uselib": 86,
        "_sysctl": 149,
        "iopl": None,
        "ioperm": None,
        "open_by_handle_at": 371,
    },
    "aarch64": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "userfaultfd": 282,
        "keyctl": 219,
        "add_key": 217,
        "request_key": 218,
        "bpf": 280,
        "perf_event_open": 241,
        "kexec_load": 104,
        "kexec_file_load": 294,
        "init_module": 105,
        "finit_module": 273,
        "delete_module": 106,
        "acct": 89,
        "swapon": 224,
        "swapoff": 225,
        "nfsservctl": None,
        "uselib": None,
        "_sysctl": None,
        "iopl": None,
        "ioperm": None,
        "open_by_handle_at": 265,
    },
    "riscv64": {
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "userfaultfd": 282,
        "keyctl": 219,
        "add_key": 217,
        "request_key": 218,
        "bpf": 280,
        "perf_event_open": 241,
        "kexec_load": 104,
        "kexec_file_load": 294,
        "init_module": 105,
        "finit_module": 273,
        "delete_module": 106,
        "acct": 89,
        "swapon": 224,
        "swapoff": 225,
        "nfsservctl": 42,
        "uselib": None,
        "_sysctl": None,
        "iopl": None,
        "ioperm": None,
        "open_by_handle_at": 265,
    },
}


class SockFilter(ctypes.Structure):
    """One classic BPF instruction, from <linux/filter.h>."""

    _fields_ = (
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    )


class SockFprog(ctypes.Structure):
    """The program struct ``prctl(PR_SET_SECCOMP, ...)`` takes."""

    _fields_ = (
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(SockFilter)),
    )


def should_install_seccomp() -> bool:
    """Return True unless the user opted out via ``CD_NO_SECCOMP=1``."""
    return os.environ.get("CD_NO_SECCOMP", "").strip().lower() not in _TRUTHY


def _arch_name() -> str:
    from chroot_distro.arch import get_device_cpu_arch

    return get_device_cpu_arch()


def build_filter(host_arch: str) -> SockFprog | None:
    """Return the denylist program for *host_arch*, or None when unknown.

    The shape: load `arch`; one jump per arch this host runs binaries as
    natively or in compat, each landing on that arch's own compare chain,
    anything else on ALLOW. A compat arch gets its own numbers, because the
    same syscall has a different number there and judging a 32-bit binary by
    the 64-bit table denies syscalls it legitimately makes. Each chain loads
    `nr` (shared: the value only depends on the process, never on the arch)
    and runs one compare per denylisted number, falling through to ERRNO on
    a hit and past it on a miss. Jump offsets count from the *next*
    instruction and must stay forward-only and in range, or the kernel
    rejects the program with EINVAL.
    """
    archs = _ARCHS_BY_HOST.get(host_arch)
    if archs is None:
        return None

    # One compare chain per arch value, each with its own deny numbers.
    chains: list[list[int]] = []
    for arch_value in archs:
        arch_key = _ARCH_TO_TABLE.get(arch_value)
        numbers = _SYSCALL_NR.get(arch_key) if arch_key else None
        if numbers is None:
            return None
        chains.append([nr for nr in numbers.values() if nr is not None])

    program: list[SockFilter] = [SockFilter(BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH)]
    # The arch jumps dispatch to the chain for their arch; every chain starts
    # with its own load-nr. Index math: 1 arch load + len(archs) jumps, then
    # per chain 1 load-nr + 2 insns per deny number, then the final ALLOW.
    chain_starts: list[int] = []
    cursor = 1 + len(archs)
    for deny in chains:
        chain_starts.append(cursor)
        cursor += 1 + 2 * len(deny)
    allow_index = cursor
    for i, arch_value in enumerate(archs):
        jump_index = 1 + i
        # A match jumps to that arch's chain. A miss falls through to the
        # next arch compare (jf=0); only the last compare's miss goes to
        # ALLOW, which is what ends the chain.
        jf = 0 if i + 1 < len(archs) else allow_index - (jump_index + 1)
        program.append(
            SockFilter(
                BPF_JMP_JEQ_K,
                chain_starts[i] - (jump_index + 1),
                jf,
                arch_value,
            )
        )
    for deny in chains:
        chain_base = len(program)
        program.append(SockFilter(BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_NR))
        for j, nr in enumerate(deny):
            # Hit: fall through to the ERRNO return (next insn). Miss: jump
            # over it to the next compare, and past the whole chain to ALLOW
            # for the last one, whose miss otherwise runs into the next
            # chain's load-nr.
            compare_index = chain_base + 1 + 2 * j
            miss = 1 if j + 1 < len(deny) else allow_index - (compare_index + 1)
            program.append(SockFilter(BPF_JMP_JEQ_K, 0, miss, nr))
            program.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 1))
    program.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))

    arr = (SockFilter * len(program))(*program)
    return SockFprog(len(program), arr)


def install_guest_filter() -> bool:
    """Install the denylist filter in the current process. Returns success.

    Must run while the process can still install filters: as root, inside a
    user namespace, or with no_new_privs set. Best-effort, because a container
    that will not start is worse than one running without a filter.
    """
    if not should_install_seccomp():
        log.debug("seccomp disabled via CD_NO_SECCOMP=1")
        return False
    host_arch = _arch_name()
    fprog = build_filter(host_arch)
    if fprog is None:
        log.debug("no seccomp table for arch %r, skipping filter", host_arch)
        return False
    result = libc_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog))
    if result != 0:
        log.debug("PR_SET_SECCOMP failed (%d), running without a filter", result)
        return False
    return True
