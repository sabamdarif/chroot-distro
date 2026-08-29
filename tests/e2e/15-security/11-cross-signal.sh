#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify cross-signal blocking

set -e

# Start a host process, try to signal it from inside container
sleep 9999 &
bystander_pid=$!
echo "Host bystander PID: $bystander_pid"
output=$(sudo chroot-distro login debian-sec --isolated -- \
  sh -c "kill -0 $bystander_pid 2>&1 || echo SIGNAL_BLOCKED")
echo "$output"
kill $bystander_pid 2>/dev/null || true
if echo "$output" | grep -q "SIGNAL_BLOCKED\|No such process"; then
	echo "PASS: Cross-boundary signal blocked"
else
	echo "FAIL: Container could signal host process!"
	exit 1
fi
