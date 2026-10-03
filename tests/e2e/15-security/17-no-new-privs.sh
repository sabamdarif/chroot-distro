#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: --no-new-privs must stop a guest setuid binary from elevating

set -e

# A setuid-root copy of a root-readable file reader: `cat` with a wrapper is
# not setuid-safe to build here, so the probe is the kernel bit itself plus a
# guest setuid binary that only root can read.
probe='
import ctypes, os
libc = ctypes.CDLL(None)
v = libc.prctl(39, 0, 0, 0, 0)  # PR_GET_NO_NEW_PRIVS
print("NNP=%d" % v)
'

# Without the flag: NNP must be 0.
out=$(sudo chroot-distro login debian-sec -- python3 -c "$probe")
echo "$out"
echo "$out" | grep -q "NNP=0" || { echo "FAIL: NNP set without --no-new-privs"; exit 1; }
echo "PASS: default keeps no_new_privs off"

# With the flag: NNP must be 1.
out=$(sudo chroot-distro login debian-sec --no-new-privs -- python3 -c "$probe")
echo "$out"
echo "$out" | grep -q "NNP=1" || { echo "FAIL: --no-new-privs did not set the bit"; exit 1; }
echo "PASS: --no-new-privs sets PR_SET_NO_NEW_PRIVS"

# And the env var form must reach across the sudo elevation.
out=$(CD_NO_NEW_PRIVS=1 sudo chroot-distro login debian-sec -- python3 -c "$probe")
echo "$out"
echo "$out" | grep -q "NNP=1" || { echo "FAIL: CD_NO_NEW_PRIVS was stripped by elevation"; exit 1; }
echo "PASS: CD_NO_NEW_PRIVS forwarded across elevation"
