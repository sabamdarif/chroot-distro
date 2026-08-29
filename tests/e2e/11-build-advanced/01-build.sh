#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (advanced): run chroot-distro build
# Needs: 00-context.sh (/tmp/adv-build, /tmp/adv-secret.txt).

set -e

sudo chroot-distro build /tmp/adv-build \
  -t test-build-adv:latest \
  --build-arg APP_VERSION=2.5.1 \
  --secret id=apikey,src=/tmp/adv-secret.txt \
  --progress plain \
  --install-as test-build-adv 2>&1 | tee /tmp/adv-build-1.log
echo "PASS: Advanced build completed"
