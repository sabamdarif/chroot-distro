#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Kill: httpd after foreground test
# Needs: 01-run-and-verify.sh, whose httpd outlives it.

set -e

sudo chroot-distro kill httpd
