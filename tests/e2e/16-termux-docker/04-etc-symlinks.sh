#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: the guest's escaping /etc symlinks resolve inside the rootfs
# Needs: 00-install.sh (termux-docker).

set -e

output=$(sudo chroot-distro login termux-docker -- readlink /etc/passwd)
echo "$output"
# Still the image's own symlink: nothing replaced it with a regular file.
echo "$output" | grep -qx "/system/etc/passwd"

output=$(sudo chroot-distro login termux-docker -- readlink /system)
echo "$output"
# Relative, which is why the absolute /system/etc/passwd above cannot leave.
echo "$output" | grep -qx "data/data/com.termux/files/usr/opt/aosp"

output=$(sudo chroot-distro login termux-docker -- cat /etc/passwd)
echo "$output"
echo "$output" | grep -q "^system:x:1000:1000:"
# The image ships exactly root and system. A host /etc/passwd or /system/etc
# reached through the symlink would carry the runner's accounts too.
count=$(echo "$output" | grep -c ":")
[ "$count" -eq 2 ] || { echo "FAIL: /etc/passwd holds $count entries, so it is not the container's"; exit 1; }

# Written at install time beside those symlinks, without following one.
output=$(sudo chroot-distro login termux-docker -- \
  sh -c 'test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && cat /etc/resolv.conf')
echo "$output"
echo "$output" | grep -q "^nameserver "
echo "PASS: /etc reads and writes stayed inside the rootfs"
