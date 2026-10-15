#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build export: build once, exporting a tarball and a directory.
# Needs: 00-context.sh (/tmp/export-build, and no /tmp/export.tar or /tmp/export-dir).

set -eo pipefail

sudo chroot-distro build /tmp/export-build \
	-t test-build-export:latest \
	--export type=tar,dest=/tmp/export.tar \
	--export type=local,dest=/tmp/export-dir \
	--progress plain 2>&1 | tee /tmp/export-build.log

grep -q "Exporting the rootfs" /tmp/export-build.log
test -f /tmp/export.tar
test -d /tmp/export-dir
echo "PASS: build with both export types completed"
