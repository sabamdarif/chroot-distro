#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (output): --install-as refuses a name already installed
# Needs: 02-build.sh (the name it must refuse).

set -e

set +e
sudo chroot-distro build /tmp/out-build -t test-build-out:latest \
  --install-as test-build-out --progress plain > /tmp/taken.log 2>&1
rc=$?
set -e
cat /tmp/taken.log
[ "$rc" -ne 0 ] || { echo "FAIL: a name that is already installed was accepted"; exit 1; }
grep -qF "already exists" /tmp/taken.log
# The refusal comes before the build, so the container stands.
sudo chroot-distro login test-build-out -- cat /app-mode.txt | grep -qx "prod"
echo "PASS: the taken name was refused and the container untouched"
