#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Multi-platform build: two platforms, one archive, one installed container.
# Needs: 00-context.sh (/tmp/multi-build).
#
# The runner is amd64 and no emulator is assumed, so the arm64 half of this
# warns that none is registered and builds anyway: its stages carry no RUN.
# --install-as therefore has exactly one platform it can install, which is the
# one the next steps read back.

set -eo pipefail

sudo chroot-distro build /tmp/multi-build \
  -t test-build-multi:latest \
  --platform linux/amd64,linux/arm64 \
  -o /tmp/multi-build.oci.tar \
  --progress plain \
  --install-as test-build-multi 2>&1 | tee /tmp/multi-build.log

grep -q "Layers (linux/amd64)" /tmp/multi-build.log
grep -q "Layers (linux/arm64)" /tmp/multi-build.log
echo "PASS: both platforms were built and reported"
