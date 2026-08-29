#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: debian works after reset

set -e

output=$(sudo chroot-distro login debian -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "debian"
echo "PASS: Debian container works after reset"
