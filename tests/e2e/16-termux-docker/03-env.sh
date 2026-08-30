#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: the session environment the termux branch and the image config produce
# Needs: 00-install.sh (termux-docker).

set -e

output=$(sudo chroot-distro login termux-docker -- env)
echo "--- guest env ---"
echo "$output"
echo "--- end ---"
echo "$output" | grep -qx "PREFIX=/data/data/com.termux/files/usr"
echo "$output" | grep -qx "HOME=/data/data/com.termux/files/home"
echo "$output" | grep -qx "TMPDIR=/data/data/com.termux/files/usr/tmp"
echo "$output" | grep -qx "ANDROID_ROOT=/system"
# Contains, not equals: login execs a login shell, which sources the guest's
# own $PREFIX/etc/profile and rebuilds PATH.
echo "$output" | grep -E "^PATH=" | grep -qF "/data/data/com.termux/files/usr/bin"
echo "PASS: PREFIX, HOME, TMPDIR, ANDROID_ROOT and PATH are the guest's own"
