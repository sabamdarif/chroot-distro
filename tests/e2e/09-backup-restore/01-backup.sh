#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Backup: alpine-test

set -e

sudo chroot-distro backup alpine-test -o /tmp/alpine-test-backup.tar.gz
ls -lh /tmp/alpine-test-backup.tar.gz
echo "PASS: Backup created successfully"
