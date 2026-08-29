#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Sync: host directory to container

set -e

mkdir -p /tmp/sync-src
echo "sync-test-content" > /tmp/sync-src/testfile.txt
sudo chroot-distro sync /tmp/sync-src alpine-test:/tmp/sync-dest
output=$(sudo chroot-distro login alpine-test -- cat /tmp/sync-dest/testfile.txt)
echo "$output"
echo "$output" | grep -q "sync-test-content"
echo "PASS: Sync works correctly"
