#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Run: the image's /entrypoint.sh with Cmd replaced by trailing args
# Needs: 00-install.sh (termux-docker).

set -e

# /entrypoint.sh has shebang /system/bin/sh, which resolves only through the
# guest's own /system symlink, and takes its non-root branch at uid 1000.
output=$(sudo chroot-distro run termux-docker -- id -u)
echo "$output"
echo "$output" | grep -qx "1000"
echo "PASS: the entrypoint ran and execed the given command"
