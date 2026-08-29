#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (advanced): rebuild uses cache + cache mount persists
# Needs: 01-build.sh, whose run populated the cache mount.

set -e

sudo chroot-distro unmount test-build-adv || true
sudo chroot-distro remove test-build-adv
# Different APP_VERSION: early layers stay CACHED, the
# cache-mount RUN re-executes and must see the marker
# written by the first build.
sudo chroot-distro build /tmp/adv-build \
  -t test-build-adv:latest \
  --build-arg APP_VERSION=2.5.2 \
  --secret id=apikey,src=/tmp/adv-secret.txt \
  --progress plain \
  --install-as test-build-adv 2>&1 | tee /tmp/adv-build-2.log
grep -q "CACHED" /tmp/adv-build-2.log
echo "PASS: rebuild reused cached layers"

sudo chroot-distro login test-build-adv -- cat /opt/app/version.txt | grep -qx "version=2.5.2"
echo "PASS: changed --build-arg invalidated dependent layer"

sudo chroot-distro login test-build-adv -- cat /opt/app/cachemount.txt | grep -qx "cache-hit"
echo "PASS: RUN --mount=type=cache persisted across builds"
