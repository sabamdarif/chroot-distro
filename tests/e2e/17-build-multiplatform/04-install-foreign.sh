#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Multi-platform verify: the tag holds the other platform too, offline.
# Needs: 01-build.sh (the tag test-build-multi:latest in the local cache).
#
# One manifest cache entry per (tag, platform) is what lets the foreign half of
# a matrix be installed by name after the build, so this install must not reach
# the network: every blob it needs was published by the build.

set -eo pipefail

sudo chroot-distro install test-build-multi:latest \
  --architecture arm64 \
  --name test-build-multi-arm 2>&1 | tee /tmp/multi-install-arm.log

grep -qi "is cached" /tmp/multi-install-arm.log
echo "PASS: the arm64 platform installed from the local cache"

# The ARCH column is read out of the rootfs's own ELF headers, so nothing here
# executes the foreign guest.
sudo chroot-distro info 2>&1 | tee /tmp/multi-info.txt > /dev/null
grep "test-build-multi-arm" /tmp/multi-info.txt | grep -q "aarch64"
echo "PASS: the installed rootfs is the aarch64 one"
