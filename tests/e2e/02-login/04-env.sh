#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: Debian --env injection

set -e

output=$(sudo chroot-distro login debian --env TEST_VAR=hello123 -- printenv TEST_VAR)
echo "$output"
echo "$output" | grep -q "hello123"
