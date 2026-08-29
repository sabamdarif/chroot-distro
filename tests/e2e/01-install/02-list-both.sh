#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: list shows both containers
# Needs: 00-alpine.sh and 01-debian.sh.

set -e

output=$(sudo chroot-distro list 2>&1)
echo "$output"
echo "$output" | grep -q "alpine"
echo "$output" | grep -q "debian"
