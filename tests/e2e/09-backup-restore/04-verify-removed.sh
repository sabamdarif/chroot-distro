#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: alpine-test removed from list

set -e

output=$(sudo chroot-distro list 2>&1)
echo "$output"
if echo "$output" | grep -q "alpine-test"; then
	echo "FAIL: Container not removed!"
	exit 1
fi
echo "PASS: Container removed successfully"
