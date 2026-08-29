#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (output): the archive checker itself parses.

set -e

here=$(cd "$(dirname "$0")" && pwd)

python3 -c "compile(open('$here/verify-oci.py').read(), 'verify-oci.py', 'exec')"
echo "PASS: checker parses"
