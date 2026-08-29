#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 6: Namespace Isolation (CD_USE_NS=1)
# Namespace: Debian login with CD_USE_NS=1
# Needs: 01-install (debian).

set -e

output=$(sudo env CD_USE_NS=1 chroot-distro login debian -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "debian"
if echo "$output" | grep -qi "ID=ubuntu"; then
	echo "FAIL: Host OS leaked under namespace isolation!"
	exit 1
fi
echo "PASS: Namespace isolation shows correct OS"
