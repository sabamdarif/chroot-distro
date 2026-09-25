#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: default-mode mount hardening (nosuid,nodev,noexec)
# Needs: 01-install (alpine).

set -e

# nosuid,nodev,noexec are plain VFS flags applied in every mode, not only
# --isolated. /proc and the fresh devpts are mounted in the default login on
# every host, so their flags are checked here; /dev/shm is only a fresh tmpfs
# when the host lacks one, so it is not asserted in this always-on test.
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
