#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Unmount: alpine-test after sync
# Needs: 07-management/00-rename.sh (alpine-test).

set -e

sudo chroot-distro unmount alpine-test || true
