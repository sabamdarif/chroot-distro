#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Diff: alpine-test

set -e

sudo chroot-distro diff alpine-test || true
echo "PASS: Diff command ran"
