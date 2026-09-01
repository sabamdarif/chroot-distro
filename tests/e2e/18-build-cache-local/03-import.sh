#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Local cache: nothing left locally, and the folder serves the step anyway.
# Needs: 00-context.sh (/tmp/cache-build), 01-export.sh (/tmp/cache-dir).
#
# The whole download cache goes first, index, layers and manifests alike, so the
# RUN below can only report CACHED if its layer came back out of the folder. This
# is the last suite, so nothing after it reads what is dropped here; the base
# image is re-pulled by the build itself.

set -eo pipefail

sudo chroot-distro clear-cache

sudo chroot-distro build /tmp/cache-build \
  -t test-build-cache:latest \
  --cache-from type=local,src=/tmp/cache-dir \
  --progress plain \
  --install-as test-build-cache 2>&1 | tee /tmp/cache-import.log

grep -q "Imported 1 cached step(s) from '/tmp/cache-dir'" /tmp/cache-import.log
grep -q "CACHED" /tmp/cache-import.log
echo "PASS: the step was served out of the folder"
