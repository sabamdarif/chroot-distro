#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Restore: from backup
# Needs: 01-backup.sh (/tmp/alpine-test-backup.tar.gz).

set -e

sudo chroot-distro restore /tmp/alpine-test-backup.tar.gz
output=$(sudo chroot-distro list 2>&1)
echo "$output"
echo "$output" | grep -q "alpine-test"
echo "PASS: Container restored from backup"
