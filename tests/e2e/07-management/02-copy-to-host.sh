#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Copy: file from container to host

set -e

sudo chroot-distro copy alpine-test:/etc/hostname ./hostname-test
echo "Copied hostname:"
cat ./hostname-test
