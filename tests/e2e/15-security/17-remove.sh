#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Remove: debian-sec

set -e

sudo chroot-distro remove debian-sec || true
