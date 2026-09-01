#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Local cache verify: the rootfs the folder rebuilt is the one it recorded.
# Needs: 03-import.sh (the test-build-cache container).

set -e

output=$(sudo chroot-distro login test-build-cache -- cat /cached.txt)
echo "$output"
echo "$output" | grep -q "chroot-distro-cache-test"
echo "PASS: the cached layer carried the content the RUN produced"
