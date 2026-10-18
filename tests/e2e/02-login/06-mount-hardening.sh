#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: default-mode mount hardening (nosuid,nodev,noexec) and the fresh
# pseudo-filesystems every mode mounts (tmpfs /dev, read-only sysfs).
# Needs: 01-install (alpine).

set -e

# nosuid,nodev,noexec are plain VFS flags applied in every mode, not only
# --isolated. /proc, the fresh devpts, the tmpfs /dev and the fresh sysfs are
# mounted in the default login on every host; on a host whose kernel or
# SELinux refuses a fresh mount the code falls back to the host bind, so a
# fallback fstype (devtmpfs, or a bound sysfs) is accepted with a warning in
# the output instead of a failure.
mounts=$(sudo chroot-distro login alpine -- cat /proc/mounts)
echo "$mounts"

check() {
	local target=$1
	shift
	local line
	line=$(echo "$mounts" | awk -v t="$target" '$2 == t {print; exit}')
	if [ -z "$line" ]; then
		echo "FAIL: $target not mounted"
		exit 1
	fi
	for flag in "$@"; do
		if ! echo "$line" | grep -qw "$flag"; then
			echo "FAIL: $target missing $flag: $line"
			exit 1
		fi
	done
	echo "PASS: $target has $*"
}

check /proc nosuid nodev noexec
check /dev/pts nosuid noexec

dev_line=$(echo "$mounts" | awk '$2 == "/dev" {print; exit}')
if [ -z "$dev_line" ]; then
	echo "FAIL: /dev not mounted"
	exit 1
fi
case "$dev_line" in
	tmpfs\ *) echo "PASS: /dev is a fresh tmpfs" ;;
	*)
		echo "WARN: /dev is not tmpfs (host bind fallback): $dev_line"
		;;
esac

sys_line=$(echo "$mounts" | awk '$2 == "/sys" {print; exit}')
if [ -z "$sys_line" ]; then
	echo "FAIL: /sys not mounted"
	exit 1
fi
case "$sys_line" in
	sysfs\ *)
		check /sys ro nosuid nodev noexec
		;;
	*)
		echo "WARN: /sys is not a fresh sysfs (host bind fallback): $sys_line"
		;;
esac

# The fresh /dev carries the six default nodes and the /proc/self/fd links.
sudo chroot-distro login alpine -- sh -c '
set -e
for n in null zero full random urandom tty; do
	[ -c "/dev/$n" ] || { echo "FAIL: /dev/$n missing"; exit 1; }
done
for l in fd stdin stdout stderr; do
	[ -L "/dev/$l" ] || { echo "FAIL: /dev/$l is not a symlink"; exit 1; }
done
[ "$(readlink /dev/fd)" = /proc/self/fd ] || { echo "FAIL: /dev/fd target"; exit 1; }
echo PASS: /dev nodes and symlinks
'
