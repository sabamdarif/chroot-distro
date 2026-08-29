#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (output): build with two --output archives
# Needs: 00-context.sh (/tmp/out-build).

set -eo pipefail

sudo chroot-distro build /tmp/out-build \
  -t test-build-out:latest \
  --build-arg LD_AUDIT=./audit-passed.so \
  -o /tmp/out-build.tar \
  -o /tmp/out-build.tar.gz \
  --progress plain \
  --install-as test-build-out 2>&1 | tee /tmp/out-build.log
echo "PASS: build with --output completed"
