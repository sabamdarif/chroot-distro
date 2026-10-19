#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build export refuse: a destination that already exists ends the build.
# Needs: 01-build.sh (/tmp/export.tar exists).

set -eo pipefail

if sudo sh -c 'chroot-distro build /tmp/export-build \
	-t test-build-export:latest \
	--export type=tar,dest=/tmp/export.tar \
	--progress plain >/tmp/export-refuse.log 2>&1'; then
	echo "FAIL: an existing --export dest was not refused"
	exit 1
fi
grep -q "already exists" /tmp/export-refuse.log
echo "PASS: an existing --export dest is refused"
