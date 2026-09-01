#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Local cache: build once, and write the folder the next build reads.
# Needs: 00-context.sh (/tmp/cache-build, and no /tmp/cache-dir).
#
# --cache-from is pointed at a folder that does not exist yet, which is the first
# build in a fresh checkout: it imports nothing and is not an error. The reads
# below are unprivileged on purpose, since the build is root and whoever archives
# what it wrote is usually not.

set -eo pipefail

sudo chroot-distro build /tmp/cache-build \
  -t test-build-cache:latest \
  --cache-from type=local,src=/tmp/cache-dir \
  --cache-to type=local,dest=/tmp/cache-dir \
  --progress plain 2>&1 | tee /tmp/cache-export.log

grep -q "Imported 0 cached step(s) from '/tmp/cache-dir'" /tmp/cache-export.log
grep -q "Exported 1 cached step(s)" /tmp/cache-export.log
test -r /tmp/cache-dir/build-cache.json
test "$(find /tmp/cache-dir/blobs -type f | wc -l)" -eq 1
echo "PASS: one step exported into a folder that did not exist"
