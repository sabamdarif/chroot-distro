#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: exit code of inner command propagates

set -e

sudo chroot-distro login alpine -- true
echo "PASS: exit 0 propagates"
if sudo chroot-distro login alpine -- false; then
	echo "FAIL: 'login -- false' exited 0"; exit 1
fi
sudo chroot-distro login alpine -- sh -c 'exit 42' && rc=0 || rc=$?
[ "$rc" -eq 42 ] || { echo "FAIL: expected exit 42, got $rc"; exit 1; }
echo "PASS: non-zero exit codes propagate"
