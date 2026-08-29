#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify PID namespace isolation

set -e

# A host-only PID should not be visible inside container
sleep 9999 &
host_pid=$!
output=$(sudo chroot-distro login debian-sec --isolated -- \
  sh -c "ls /proc/$host_pid/ 2>&1 || echo PID_HIDDEN")
echo "$output"
kill $host_pid 2>/dev/null || true
if echo "$output" | grep -q "PID_HIDDEN\|No such file"; then
	echo "PASS: Host PID not visible in container (PID namespace isolated)"
else
	echo "FAIL: Host PID visible in container!"
	exit 1
fi
