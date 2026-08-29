#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Isolation: Alpine --isolated login
# Needs: 01-install (alpine).

set -e

output=$(sudo chroot-distro login alpine --isolated -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "alpine"
if echo "$output" | grep -qi "ID=ubuntu"; then
	echo "FAIL: Host OS leaked into isolated container!"
	exit 1
fi
echo "PASS: Isolated container shows correct OS"
