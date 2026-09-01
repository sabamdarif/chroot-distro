#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Local cache: a context whose RUN is worth caching, and no cache folder yet.
#
# The RUN writes a marker a later step reads back out of the installed rootfs, so
# a build served entirely from the folder is held to having produced the same
# tree as the build that filled it.

set -e

rm -rf /tmp/cache-build /tmp/cache-dir /tmp/not-a-cache
mkdir -p /tmp/cache-build
cat > /tmp/cache-build/Dockerfile << 'DOCKERFILE'
FROM alpine:latest
RUN echo "chroot-distro-cache-test" > /cached.txt
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/cache-build/Dockerfile
