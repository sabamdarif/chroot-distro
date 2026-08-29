#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Remove: test-build-add

set -e

sudo chroot-distro unmount test-build-add || true
sudo chroot-distro remove test-build-add
