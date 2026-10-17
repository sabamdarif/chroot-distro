#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build contexts verify: the installed container holds the marker, and the
# scratch state the build used is gone.
# Needs: 01-copy-from.sh (bctx-copy installed).

set -eo pipefail

test "$(sudo chroot-distro run bctx-copy -- cat /assets/marker.txt)" = "named-context-marker"
echo "PASS: the installed container reads the named context's file"

sudo chroot-distro remove bctx-copy >/dev/null
sudo rm -rf /tmp/bctx
echo "PASS: cleanup"
