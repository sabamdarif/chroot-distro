#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: the derived alias is listed, and info reads the arch off $PREFIX/bin/bash
# Needs: 00-install.sh (termux-docker).

set -e

output=$(sudo chroot-distro list 2>&1)
echo "$output"
echo "$output" | grep -q "termux-docker"

host_arch=$(uname -m)
output=$(sudo chroot-distro info 2>&1)
row=$(echo "$output" | grep -E "^[[:space:]]+termux-docker[[:space:]]")
echo "$row"
# An image with no /bin or /usr/bin: only the $PREFIX/bin/bash candidate in
# detect_installed_arch can answer, and "unknown" means it stopped answering.
echo "$row" | grep -qw "$host_arch"
echo "PASS: the alias is termux-docker and its arch reads as $host_arch"
