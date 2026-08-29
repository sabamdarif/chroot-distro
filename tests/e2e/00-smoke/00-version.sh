#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 0: Smoke Tests
# Smoke: --version

set -e

chroot-distro --version
