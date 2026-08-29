#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 4: httpd Service Test (foreground)
# Install: httpd

set -e

sudo chroot-distro install httpd:latest
