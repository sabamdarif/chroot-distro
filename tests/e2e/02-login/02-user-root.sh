#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: Debian --user root

set -e

output=$(sudo chroot-distro login debian --user root -- whoami)
echo "$output"
echo "$output" | grep -q "root"
