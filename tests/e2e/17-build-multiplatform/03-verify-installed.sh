#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Multi-platform verify: --install-as installed the platform this host runs.
# Needs: 01-build.sh (the container test-build-multi).

set -eo pipefail

report=$(sudo chroot-distro login test-build-multi -- cat /report)
echo "$report"

echo "$report" | grep -qx "target=linux/amd64"
echo "PASS: --install-as picked the host platform out of the matrix"

echo "$report" | grep -qx "ran-on=x86_64"
echo "PASS: the builder stage ran on the build platform"
