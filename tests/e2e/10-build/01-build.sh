#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build: run chroot-distro build
# Needs: 00-dockerfile.sh (/tmp/test-build-context).

set -e

sudo chroot-distro build /tmp/test-build-context \
  -t test-build:latest \
  --install-as test-build
echo "PASS: Build completed"
