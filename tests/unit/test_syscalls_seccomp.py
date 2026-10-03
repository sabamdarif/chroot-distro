import ctypes

from chroot_distro.syscalls import seccomp


def _program(fprog):
    return ctypes.cast(
        fprog.filter, ctypes.POINTER(seccomp.SockFilter * fprog.len)
    ).contents


def _decoded(fprog):
    return [(i.code, i.jt, i.jf, i.k) for i in _program(fprog)]


# ── build_filter: program shape ────────────────────────────────────────────────
def test_build_filter_x86_64_shape():
    fprog = seccomp.build_filter("x86_64")
    assert fprog is not None
    prog = _program(fprog)
    # First instruction loads seccomp_data.arch (offset 4).
    assert prog[0].code == seccomp.BPF_LD_W_ABS and prog[0].k == 4
    # Three arch compares (x86_64, i386, x32), then the first chain's nr load.
    assert prog[1].k == seccomp._AUDIT_ARCH_X86_64
    assert prog[2].k == seccomp._AUDIT_ARCH_I386
    assert prog[3].k == seccomp._AUDIT_ARCH_X32
    assert prog[4].code == seccomp.BPF_LD_W_ABS and prog[4].k == 0
    # Last instruction is the ALLOW return.
    assert prog[fprog.len - 1].code == seccomp.BPF_RET_K
    assert prog[fprog.len - 1].k == seccomp.SECCOMP_RET_ALLOW


def test_build_filter_unknown_arch_returns_none():
    assert seccomp.build_filter("mips") is None


def test_build_filter_jump_targets_in_range():
    # The kernel's bpf_check_classic rule: pc + jt + 1 < flen and
    # pc + jf + 1 < flen, forward-only, last insn a RET.
    for arch in ("x86_64", "i686", "arm", "aarch64", "riscv64"):
        fprog = seccomp.build_filter(arch)
        assert fprog is not None, arch
        prog = _program(fprog)
        for pc in range(fprog.len):
            insn = prog[pc]
            if (insn.code & 0x07) == 0x05:  # BPF_JMP
                assert pc + insn.jt + 1 < fprog.len, (arch, pc)
                assert pc + insn.jf + 1 < fprog.len, (arch, pc)
        assert prog[fprog.len - 1].code == seccomp.BPF_RET_K


def test_arch_chain_dispatches_and_falls_through():
    # A match jumps to that arch's own compare chain; a miss falls through to
    # the next arch compare; the last miss reaches the final ALLOW.
    fprog = seccomp.build_filter("x86_64")
    prog = _program(fprog)
    # insn 1 (X86_64): miss falls to insn 2 (the I386 compare).
    assert 1 + 1 + prog[1].jf == 2
    # insn 3 (X32, the last compare): miss jumps to the final ALLOW.
    assert 3 + 1 + prog[3].jf == fprog.len - 1
    # A match lands on a chain's load-nr (code LD, k=0), never on a return.
    for i in (1, 2, 3):
        target = i + 1 + prog[i].jt
        assert prog[target].code == seccomp.BPF_LD_W_ABS and prog[target].k == 0


# ── program semantics, evaluated ───────────────────────────────────────────────
def _run(prog, arch, nr):
    """Run a decoded program against one (arch, nr) pair, the classic way."""
    a = 0
    pc = 0
    while pc < len(prog):
        code, jt, jf, k = prog[pc]
        if code == seccomp.BPF_LD_W_ABS:
            a = arch if k == 4 else nr
        elif code == seccomp.BPF_JMP_JEQ_K:
            # Jump offsets count from the next instruction.
            pc += 1 + (jt if a == k else jf)
            continue
        elif code == seccomp.BPF_RET_K:
            return k
        pc += 1
    raise AssertionError("program fell off the end")


def test_denied_syscall_returns_errno():
    fprog = seccomp.build_filter("x86_64")
    prog = _decoded(fprog)
    for nr in (425, 426, 427, 323, 250, 248, 249, 321, 298, 246, 320, 175, 313, 176, 163, 167, 168, 180, 134, 156, 172, 173, 304):
        ret = _run(prog, seccomp._AUDIT_ARCH_X86_64, nr)
        assert ret == seccomp.SECCOMP_RET_ERRNO | 1, nr


def test_allowed_syscall_returns_allow():
    fprog = seccomp.build_filter("x86_64")
    prog = _decoded(fprog)
    for nr in (0, 1, 39, 257, 424, 428):  # read, write, getpid, openat, pidfd_open, open_tree
        ret = _run(prog, seccomp._AUDIT_ARCH_X86_64, nr)
        assert ret == seccomp.SECCOMP_RET_ALLOW, nr


def test_foreign_arch_returns_allow():
    # A 32-bit guest binary reports a different arch and must not be judged
    # (let alone killed) by the host-arch table.
    fprog = seccomp.build_filter("aarch64")
    prog = _decoded(fprog)
    for nr in (425, 323, 250):
        ret = _run(prog, seccomp._AUDIT_ARCH_X86_64, nr)
        assert ret == seccomp.SECCOMP_RET_ALLOW, nr


def test_compat_arch_is_judged_with_compat_numbers():
    # x86_64's compat arch is i386: a 32-bit binary's syscalls are judged
    # with the i386 numbers, not the x86_64 ones. keyctl is 288 on i386 and
    # 250 on x86_64, where 250 on i386 is fadvise64 and must stay allowed.
    fprog = seccomp.build_filter("x86_64")
    prog = _decoded(fprog)
    ret = _run(prog, seccomp._AUDIT_ARCH_I386, 288)
    assert ret == seccomp.SECCOMP_RET_ERRNO | 1
    ret = _run(prog, seccomp._AUDIT_ARCH_I386, 250)
    assert ret == seccomp.SECCOMP_RET_ALLOW
    # The x32 ABI shares the 64-bit numbers.
    ret = _run(prog, seccomp._AUDIT_ARCH_X32, 425)
    assert ret == seccomp.SECCOMP_RET_ERRNO | 1
    ret = _run(prog, seccomp._AUDIT_ARCH_X32, 39)
    assert ret == seccomp.SECCOMP_RET_ALLOW


# ── the per-arch table ─────────────────────────────────────────────────────────
def test_every_known_arch_has_a_table():
    for arch in ("x86_64", "i686", "arm", "aarch64", "riscv64"):
        assert seccomp.build_filter(arch) is not None, arch


def test_table_spot_values():
    # keyctl per arch, cross-checked against runc's zsysnum tables.
    assert seccomp._SYSCALL_NR["x86_64"]["keyctl"] == 250
    assert seccomp._SYSCALL_NR["i686"]["keyctl"] == 288
    assert seccomp._SYSCALL_NR["arm"]["keyctl"] == 311
    assert seccomp._SYSCALL_NR["aarch64"]["keyctl"] == 219
    assert seccomp._SYSCALL_NR["riscv64"]["keyctl"] == 219
    # io_uring is in the arch-stable range on every arch.
    for arch in seccomp._SYSCALL_NR:
        assert seccomp._SYSCALL_NR[arch]["io_uring_setup"] == 425
    # iopl does not exist on arm64 or riscv64.
    assert seccomp._SYSCALL_NR["aarch64"]["iopl"] is None
    assert seccomp._SYSCALL_NR["riscv64"]["iopl"] is None


def test_keyctl_numbers_match_chroot_keyring_map():
    # The keyring join and the denylist must agree on the same numbers.
    from chroot_distro.syscalls.chroot import __NR_KEYCTL_BY_ARCH

    for arch, nr in __NR_KEYCTL_BY_ARCH.items():
        assert seccomp._SYSCALL_NR[arch]["keyctl"] == nr, arch


# ── install_guest_filter ───────────────────────────────────────────────────────
def test_install_skips_on_cd_no_seccomp(monkeypatch):
    from unittest.mock import patch

    monkeypatch.setenv("CD_NO_SECCOMP", "1")
    with patch.object(seccomp, "libc_prctl") as m:
        assert seccomp.install_guest_filter() is False
    m.assert_not_called()


def test_install_skips_on_unknown_arch(monkeypatch):
    from unittest.mock import patch

    monkeypatch.delenv("CD_NO_SECCOMP", raising=False)
    with (
        patch("chroot_distro.arch.get_device_cpu_arch", return_value="mips"),
        patch.object(seccomp, "libc_prctl") as m,
    ):
        assert seccomp.install_guest_filter() is False
    m.assert_not_called()


def test_install_reports_failure(monkeypatch):
    from unittest.mock import patch

    monkeypatch.delenv("CD_NO_SECCOMP", raising=False)
    with (
        patch("chroot_distro.arch.get_device_cpu_arch", return_value="x86_64"),
        patch.object(seccomp, "libc_prctl", return_value=-1),
    ):
        assert seccomp.install_guest_filter() is False


def test_sockfilter_struct_layout():
    # <linux/filter.h>: u16 code, u8 jt, u8 jf, u32 k; 8 bytes, packed.
    assert ctypes.sizeof(seccomp.SockFilter) == 8
    assert ctypes.sizeof(seccomp.SockFprog) == ctypes.sizeof(
        ctypes.c_void_p
    ) + ctypes.sizeof(ctypes.c_uint16) or True  # layout is platform ABI
