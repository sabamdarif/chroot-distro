#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 7: Container Management Operations
# Rename: alpine -> alpine-test
# Needs: 01-install (alpine).

set -e

sudo chroot-distro rename alpine alpine-test
