#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: a move that was only a rename still reaches every entry
# Needs: 00-guest-account.sh (appuser 1500:1600).

set -e

sudo chroot-distro login alpine-test -- sh -c \
  'rm -rf /tmp/mv-src /tmp/mv-dst && mkdir -p /tmp/mv-src/sub && echo data > /tmp/mv-src/sub/f.txt'
sudo chroot-distro copy alpine-test:/tmp/mv-src alpine-test:/tmp/mv-dst --move --chown appuser
out=$(sudo chroot-distro login alpine-test -- sh -c \
  "stat -c '%n %u:%g' /tmp/mv-dst /tmp/mv-dst/sub /tmp/mv-dst/sub/f.txt")
echo "$out"
[ "$(echo "$out" | wc -l)" -eq 3 ] || { echo "FAIL: stat named fewer entries than were moved"; exit 1; }
bad=$(echo "$out" | awk '$2 != "1500:1600"' | wc -l)
[ "$bad" -eq 0 ] || { echo "FAIL: rename(2) writes nothing, and the walk after it missed $bad entries"; exit 1; }
if sudo chroot-distro login alpine-test -- test -e /tmp/mv-src; then
	echo "FAIL: the source survived the move"; exit 1
fi
echo "PASS: the moved tree was chowned after the rename"
