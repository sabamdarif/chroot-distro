#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Unmount: the --output containers

set -e

sudo chroot-distro unmount test-build-out || true
sudo chroot-distro unmount test-build-out2 || true
