#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: Debian --work-dir /tmp

set -e

output=$(sudo chroot-distro login debian --work-dir /tmp -- pwd)
echo "$output"
echo "$output" | grep -q "/tmp"
