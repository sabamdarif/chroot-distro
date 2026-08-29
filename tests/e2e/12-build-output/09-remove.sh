#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Remove: the --output containers

set -e

sudo chroot-distro remove test-build-out
sudo chroot-distro remove test-build-out2
sudo rm -f /tmp/out-build.tar /tmp/out-build.tar.gz
