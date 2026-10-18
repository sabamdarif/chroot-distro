#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Namespace: CD_USE_NS keeps the fresh tmpfs /dev and read-only sysfs.
# Needs: 01-install (debian).

set -e

mounts=$(sudo env CD_USE_NS=1 chroot-distro login debian -- cat /proc/mounts)
echo "$mounts"

dev_line=$(echo "$mounts" | awk '$2 == "/dev" {print; exit}')
case "$dev_line" in
	tmpfs\ *) echo "PASS: /dev is a fresh tmpfs under CD_USE_NS" ;;
	*)
		echo "WARN: /dev is not tmpfs (host bind fallback): $dev_line"
		;;
esac

sys_line=$(echo "$mounts" | awk '$2 == "/sys" {print; exit}')
case "$sys_line" in
	sysfs\ *ro*) echo "PASS: /sys is a fresh read-only sysfs under CD_USE_NS" ;;
	*)
		echo "WARN: /sys is not a fresh sysfs (host bind fallback): $sys_line"
		;;
esac

sudo env CD_USE_NS=1 chroot-distro login debian -- sh -c '
set -e
[ -L /dev/fd ] && [ -L /dev/stdin ] || { echo "FAIL: /dev symlinks missing"; exit 1; }
[ -c /dev/null ] && [ -c /dev/urandom ] || { echo "FAIL: /dev nodes missing"; exit 1; }
echo PASS: /dev nodes and symlinks under CD_USE_NS
'
