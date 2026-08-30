#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: the bundled bionic linker loads the guest's Android binaries
# Needs: 00-install.sh (termux-docker).

set -e

# A mode-0700 bionic ELF, runnable only because the session uid matches its owner.
output=$(sudo chroot-distro login termux-docker -- bash -c 'echo $BASH_VERSION')
echo "$output"
[ -n "$output" ] || { echo "FAIL: bash produced no version, so it did not run"; exit 1; }

output=$(sudo chroot-distro login termux-docker -- apt --version)
echo "$output"
echo "$output" | grep -qi "apt"
echo "PASS: bash and apt both load against the guest's own linker"
