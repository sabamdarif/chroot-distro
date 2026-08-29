#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: a second sync finds nothing to correct
# Needs: 02-sync-every-entry.sh (/tmp/chown-tree, already owned).

set -e

out=$(sudo chroot-distro sync /tmp/chown-tree alpine-test:/tmp/chown-tree \
  --chown appuser:appgrp -v 2>&1)
echo "$out"
if echo "$out" | grep -qE "Metadata:|file:|symlink:"; then
	echo "FAIL: the destination already carries the requested owner, yet it was corrected again"
	exit 1
fi
echo "PASS: an already-correct owner is left alone"
