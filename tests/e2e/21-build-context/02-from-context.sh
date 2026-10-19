#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build contexts: FROM <name> over a local directory is scratch plus the tree.
# Needs: 00-context.sh (/tmp/bctx/standalone). Exports the rootfs to check it.

set -eo pipefail

mkdir -p /tmp/bctx/fromctx
cat >/tmp/bctx/fromctx/Dockerfile <<'DOCKERFILE'
FROM standalone
DOCKERFILE

rm -rf /tmp/bctx/exported
sudo sh -c 'chroot-distro build /tmp/bctx/fromctx \
	-t test-build-context-from:latest \
	--export type=local,dest=/tmp/bctx/exported \
	--build-context standalone=/tmp/bctx/standalone \
	--progress plain >/tmp/bctx/from.log 2>&1' 

# The rootfs is the named directory's tree and nothing else: the file is
# there, and no base image's /etc/alpine-release came along.
test "$(cat /tmp/bctx/exported/standalone.txt)" = "standalone-file"
if test -e /tmp/bctx/exported/etc/alpine-release; then
	echo "FAIL: FROM over a local context pulled a base image"
	exit 1
fi
echo "PASS: FROM over a named local context is scratch plus the tree"
