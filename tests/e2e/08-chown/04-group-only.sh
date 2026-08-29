#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: ':GROUP' changes the group and keeps the user
# Needs: 02-sync-every-entry.sh (/tmp/chown-tree owned by uid 1500).

set -e

sudo chroot-distro sync /tmp/chown-tree alpine-test:/tmp/chown-tree --chown :0
ids=$(sudo chroot-distro login alpine-test -- stat -c '%u:%g' /tmp/chown-tree/a.txt)
echo "owner: $ids"
[ "$ids" = "1500:0" ] || { echo "FAIL: expected 1500:0, got $ids"; exit 1; }

# The uid arrives as -1 ("leave this one alone"); comparing that
# against the destination's own would make every run report the
# entry as modified for good.
out=$(sudo chroot-distro sync /tmp/chown-tree alpine-test:/tmp/chown-tree --chown :0 -v 2>&1)
echo "$out"
if echo "$out" | grep -qE "Metadata:|file:|symlink:"; then
	echo "FAIL: ':GROUP' re-corrected an entry that was already right"
	exit 1
fi
echo "PASS: only the group changed, and only once"
