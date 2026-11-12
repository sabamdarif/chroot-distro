#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Registry: stop mock registry server

set -e

pkill -f mock-registry.py 2>/dev/null || true
echo "PASS: mock registry stopped"
