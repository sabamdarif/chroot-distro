#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 5: Detach Mode Test
# Run: httpd --detach
# Needs: 04-httpd-foreground/00-install.sh.

set -e

sudo chroot-distro run --detach httpd
echo "httpd launched in detached mode"
