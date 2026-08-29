#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: built container content

set -e

output=$(sudo chroot-distro login test-build -- cat /built.txt)
echo "$output"
echo "$output" | grep -q "chroot-distro-build-test"
echo "PASS: Built container has expected content"
