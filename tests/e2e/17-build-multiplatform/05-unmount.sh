#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Unmount: the multi-platform containers

set -e

sudo chroot-distro unmount test-build-multi || true
sudo chroot-distro unmount test-build-multi-arm || true
