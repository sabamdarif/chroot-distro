#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 2: Login & Command Execution
# Login: Alpine - verify os-release
# Needs: 01-install (alpine).

set -e

output=$(sudo chroot-distro login alpine -- cat /etc/os-release)
echo "$output"
echo "$output" | grep -qi "alpine"
