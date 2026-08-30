#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: the guest is recognised as Termux-shaped, not as a normal distro
# Needs: 00-install.sh (termux-docker).

set -e

# A normal image logs in as root. This one must take its uid from the owner of
# the in-rootfs Termux home, because its binaries are mode 700.
output=$(sudo chroot-distro login termux-docker -- id -u)
echo "$output"
echo "$output" | grep -qx "1000"

# The workdir default of the termux branch, which only applies when a shell was
# found under $PREFIX/bin rather than /bin.
output=$(sudo chroot-distro login termux-docker -- pwd)
echo "$output"
echo "$output" | grep -qx "/data/data/com.termux/files/home"
echo "PASS: logged in as uid 1000 in the Termux home"
