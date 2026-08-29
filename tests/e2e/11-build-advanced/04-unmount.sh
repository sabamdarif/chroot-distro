#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Unmount: test-build-adv

set -e

sudo chroot-distro unmount test-build-adv || true
