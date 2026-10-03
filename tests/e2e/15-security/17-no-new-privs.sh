#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: --no-new-privs must stop a guest setuid binary from elevating

set -e

# The kernel bit is directly observable in /proc/self/status, which every
# image can read without python.

# Without the flag: NoNewPrivs must be 0.
out=$(sudo chroot-distro login debian-sec -- grep '^NoNewPrivs:' /proc/self/status)
echo "$out"
echo "$out" | awk -F': *' '$1=="NoNewPrivs" && $2==0 {found=1} END {exit !found}' || { echo "FAIL: NoNewPrivs set without --no-new-privs"; exit 1; }
echo "PASS: default keeps no_new_privs off"

# With the flag: NoNewPrivs must be 1.
out=$(sudo chroot-distro login debian-sec --no-new-privs -- grep '^NoNewPrivs:' /proc/self/status)
echo "$out"
echo "$out" | awk -F': *' '$1=="NoNewPrivs" && $2==1 {found=1} END {exit !found}' || { echo "FAIL: --no-new-privs did not set the bit"; exit 1; }
echo "PASS: --no-new-privs sets PR_SET_NO_NEW_PRIVS"

# And the env var form must reach the guest, as the other suites pass theirs.
out=$(sudo env CD_NO_NEW_PRIVS=1 chroot-distro login debian-sec -- grep '^NoNewPrivs:' /proc/self/status)
echo "$out"
echo "$out" | awk -F': *' '$1=="NoNewPrivs" && $2==1 {found=1} END {exit !found}' || { echo "FAIL: CD_NO_NEW_PRIVS was stripped by elevation"; exit 1; }
echo "PASS: CD_NO_NEW_PRIVS forwarded across elevation"
