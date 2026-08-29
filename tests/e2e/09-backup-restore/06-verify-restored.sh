#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: restored container works

set -e

output=$(sudo chroot-distro login alpine-test -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "alpine"
echo "PASS: Restored container is functional"
