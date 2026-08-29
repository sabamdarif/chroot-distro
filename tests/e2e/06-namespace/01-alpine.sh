#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Namespace: Alpine login with CD_USE_NS=1
# Needs: 01-install (alpine).

set -e

output=$(sudo env CD_USE_NS=1 chroot-distro login alpine -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "alpine"
if echo "$output" | grep -qi "ID=ubuntu"; then
	echo "FAIL: Host OS leaked under namespace isolation!"
	exit 1
fi
echo "PASS: Namespace isolation shows correct OS for Alpine"
