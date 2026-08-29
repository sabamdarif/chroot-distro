#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 10: Namespace Security Tests
# Regression tests for the security report findings (Tests 2,3,7).
# These verify that --isolated mode provides the expected isolation
# properties when kernel support is available.
# Security: Install Debian for security tests

set -e

sudo chroot-distro install debian:bookworm-slim --name debian-sec || true
# Ensure it's in a clean state
sudo chroot-distro unmount debian-sec 2>/dev/null || true
