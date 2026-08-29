#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Unmount: alpine-test after restore verify

set -e

sudo chroot-distro unmount alpine-test || true
