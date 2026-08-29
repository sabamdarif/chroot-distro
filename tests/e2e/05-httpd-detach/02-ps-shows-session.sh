#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: ps shows detached session

set -e

output=$(sudo chroot-distro ps 2>&1)
echo "$output"
echo "$output" | grep -qi "httpd"
echo "PASS: Detached session visible in ps"
