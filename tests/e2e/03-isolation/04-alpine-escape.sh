#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Isolation: Alpine escape attempt via /proc/1/root

set -e

output=$(sudo chroot-distro login alpine --isolated -- \
  sh -c 'cat /proc/1/root/etc/os-release 2>/dev/null || echo ESCAPE_BLOCKED')
echo "$output"
if echo "$output" | grep -qi "ID=ubuntu"; then
	echo "FAIL: Chroot escape detected!"
	exit 1
fi
echo "PASS: Escape blocked or contained"
