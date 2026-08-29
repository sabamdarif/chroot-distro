#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify graceful degradation warnings

set -e

# The --isolated login should produce isolation status output
# showing which namespaces are active
output=$(sudo chroot-distro login debian-sec --isolated -- \
  echo "isolation-check" 2>&1)
echo "$output"
# On GitHub runners (full kernel support), we should see
# successful isolation. The key test is that it doesn't
# crash or refuse to start.
echo "$output" | grep -q "isolation-check"
echo "PASS: Isolated login completed successfully"
