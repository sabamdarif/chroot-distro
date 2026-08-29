#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 3: Isolation / Escape Prevention
# Isolation: Debian --isolated login
# Needs: 01-install (debian).

set -e

output=$(sudo chroot-distro login debian --isolated -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "debian"
# Must NOT contain the host OS (Ubuntu on GitHub runners)
if echo "$output" | grep -qi "ID=ubuntu"; then
	echo "FAIL: Host OS leaked into isolated container!"
	exit 1
fi
echo "PASS: Isolated container shows correct OS"
