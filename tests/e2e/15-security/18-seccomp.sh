#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: the seccomp denylist must be installed in the guest

set -e

# Seccomp: 2 in /proc/self/status means a filter is installed; 0 means none.
# The field needs no syscall to read, so the probe works on any image.

mode() {
	sudo chroot-distro login debian-sec "$@" -- awk '$1=="Seccomp:" {gsub(/[ 	]/, "", $2); print $2}' /proc/self/status
}

# Without the hatch: the filter must be installed (mode 2).
out=$(mode)
echo "Seccomp: $out"
[ "$out" = "2" ] || { echo "FAIL: no seccomp filter in the guest (mode $out)"; exit 1; }
echo "PASS: denylist filter installed in the guest"

# The escape hatch must reach across elevation and remove the filter.
out=$(sudo env CD_NO_SECCOMP=1 chroot-distro login debian-sec -- awk '$1=="Seccomp:" {gsub(/[ 	]/, "", $2); print $2}' /proc/self/status)
echo "Seccomp (CD_NO_SECCOMP=1): $out"
[ "$out" = "0" ] || { echo "FAIL: CD_NO_SECCOMP did not disable the filter (or was stripped by elevation)"; exit 1; }
echo "PASS: CD_NO_SECCOMP forwarded and honoured"

# A normal shell and a file write still work under the filter.
out=$(sudo chroot-distro login debian-sec -- sh -c 'echo ok > /tmp/seccomp-smoke && cat /tmp/seccomp-smoke && rm /tmp/seccomp-smoke')
[ "$out" = "ok" ] || { echo "FAIL: basic guest I/O broken: $out"; exit 1; }
echo "PASS: normal guest I/O works under the filter"
