#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 8: Build Test
# Build: create test Dockerfile

set -e

mkdir -p /tmp/test-build-context
cat > /tmp/test-build-context/Dockerfile << 'DOCKERFILE'
FROM alpine:latest
RUN echo "chroot-distro-build-test" > /built.txt
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/test-build-context/Dockerfile
