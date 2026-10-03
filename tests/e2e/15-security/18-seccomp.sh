#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: the seccomp denylist must deny listed syscalls and allow the rest

set -e

# The probe: call three syscalls through libc and report their errno. kexec_load
# with null args is EINVAL (22) when the syscall runs, EPERM (1) when the filter
# denies it. io_uring_setup with null args is EFAULT (14) unfiltered, EPERM
# filtered. getpid must keep working.
probe='
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
out = []
for nr, args in ((246, (0, 0, 0, 0)), (425, (0, 0)), (39, ())):
    ctypes.set_errno(0)
    libc.syscall(nr, *args)
    out.append(ctypes.get_errno())
print("KEXEC=%d IOURING=%d GETPID=%d" % tuple(out))
'

out=$(sudo chroot-distro login debian-sec -- python3 -c "$probe")
echo "$out"
echo "$out" | grep -q "KEXEC=1" || { echo "FAIL: kexec_load not denied by the filter"; exit 1; }
echo "$out" | grep -q "IOURING=1" || { echo "FAIL: io_uring_setup not denied by the filter"; exit 1; }
echo "$out" | grep -q "GETPID=0" || { echo "FAIL: getpid broken by the filter"; exit 1; }
echo "PASS: denylist filter active in the guest"

# The escape hatch must reach across elevation and turn the filter off.
out=$(CD_NO_SECCOMP=1 sudo chroot-distro login debian-sec -- python3 -c "$probe")
echo "$out"
if echo "$out" | grep -q "KEXEC=1"; then
	echo "FAIL: CD_NO_SECCOMP did not disable the filter (or was stripped by elevation)"
	exit 1
fi
echo "PASS: CD_NO_SECCOMP forwarded and honoured"

# A normal shell and a file write still work under the filter.
out=$(sudo chroot-distro login debian-sec -- sh -c 'echo ok > /tmp/seccomp-smoke && cat /tmp/seccomp-smoke && rm /tmp/seccomp-smoke')
[ "$out" = "ok" ] || { echo "FAIL: basic guest I/O broken: $out"; exit 1; }
echo "PASS: normal guest I/O works under the filter"
