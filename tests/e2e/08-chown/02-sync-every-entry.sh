#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: sync gives every entry the named owner
# Needs: 00-guest-account.sh (appuser 1500:1600).

set -e

rm -rf /tmp/chown-tree
mkdir -p /tmp/chown-tree/sub
echo alpha > /tmp/chown-tree/a.txt
echo beta > /tmp/chown-tree/sub/b.txt
ln -sf a.txt /tmp/chown-tree/link
sudo chroot-distro sync /tmp/chown-tree alpine-test:/tmp/chown-tree --chown appuser:appgrp

# stat without -L, so the symlink reports its own owner rather
# than its target's: the flag is applied with lchown.
out=$(sudo chroot-distro login alpine-test -- sh -c \
  "stat -c '%n %u:%g' /tmp/chown-tree /tmp/chown-tree/a.txt \
     /tmp/chown-tree/sub /tmp/chown-tree/sub/b.txt /tmp/chown-tree/link")
echo "$out"
[ "$(echo "$out" | wc -l)" -eq 5 ] || { echo "FAIL: stat named fewer entries than were synced"; exit 1; }
bad=$(echo "$out" | awk '$2 != "1500:1600"' | wc -l)
[ "$bad" -eq 0 ] || { echo "FAIL: $bad entries not owned 1500:1600"; exit 1; }
echo "PASS: file, nested file, directory and symlink all owned 1500:1600"
