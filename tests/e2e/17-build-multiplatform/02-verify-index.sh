#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Multi-platform verify: the archive is one index over both platforms.
# Needs: 01-build.sh (/tmp/multi-build.oci.tar), verify-index.py.

set -eo pipefail

here=$(cd "$(dirname "$0")" && pwd)

# Root-owned: the archive is published from a 0600 temporary. The platforms are
# named in the order they were asked for, which the index has to keep.
sudo python3 "$here/verify-index.py" /tmp/multi-build.oci.tar linux/amd64 linux/arm64 | tee /tmp/multi-index.txt

grep -qx "index 2 platforms" /tmp/multi-index.txt
echo "PASS: one index, two platform manifests, each config and report its own"
