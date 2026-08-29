#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: copy resolves the name in the container
# Needs: 00-guest-account.sh (appuser 1500:1600).

set -e

echo "chown-copy-content" > /tmp/chown-src.txt
sudo chroot-distro copy /tmp/chown-src.txt alpine-test:/tmp/chown-copy.txt --chown appuser
ids=$(sudo chroot-distro login alpine-test -- stat -c '%u:%g' /tmp/chown-copy.txt)
echo "owner: $ids"
[ "$ids" = "1500:1600" ] || { echo "FAIL: expected 1500:1600, got $ids"; exit 1; }
echo "PASS: --chown appuser landed as 1500:1600 (primary group read from passwd)"
