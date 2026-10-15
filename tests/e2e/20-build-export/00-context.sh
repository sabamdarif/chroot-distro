#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build export: a context whose rootfs is worth reading back.
#
# The RUN writes a marker the verification reads out of the exported tree, and
# the build is given a non-root file owner, so the export is held to numeric
# ownership surviving rather than flattened to root.

set -e

rm -rf /tmp/export-build /tmp/export.tar /tmp/export-dir
mkdir -p /tmp/export-build
cat >/tmp/export-build/Dockerfile <<'DOCKERFILE'
FROM alpine:latest
RUN echo "chroot-distro-export-test" > /export-marker.txt
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/export-build/Dockerfile
