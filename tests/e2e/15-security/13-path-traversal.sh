#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify path traversal blocked

set -e

output=$(sudo chroot-distro login debian-sec --isolated -- \
  sh -c 'cat /proc/self/root/../../../../etc/hostname 2>&1')
echo "$output"
host_hostname=$(hostname)
if echo "$output" | grep -q "$host_hostname"; then
	echo "FAIL: Path traversal reached host filesystem!"
	exit 1
fi
echo "PASS: Path traversal contained within container"
