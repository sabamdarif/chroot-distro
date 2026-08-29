#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: numeric ids are taken as they stand
# Needs: 01-copy-in-container.sh (/tmp/chown-src.txt).

set -e

sudo chroot-distro copy /tmp/chown-src.txt alpine-test:/tmp/chown-num.txt --chown 4242:4243
ids=$(sudo chroot-distro login alpine-test -- stat -c '%u:%g' /tmp/chown-num.txt)
echo "owner: $ids"
[ "$ids" = "4242:4243" ] || { echo "FAIL: expected 4242:4243, got $ids"; exit 1; }
echo "PASS: an id with no passwd entry is still reachable"
