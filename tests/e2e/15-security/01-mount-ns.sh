#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify mount namespace isolation
# Needs: 00-install.sh (debian-sec).

set -e

# Host and container mount namespaces should differ
host_mnt=$(readlink /proc/self/ns/mnt)
container_mnt=$(sudo chroot-distro login debian-sec --isolated -- \
  readlink /proc/self/ns/mnt)
echo "Host mnt ns: $host_mnt"
echo "Container mnt ns: $container_mnt"
if [ "$host_mnt" = "$container_mnt" ]; then
	echo "FAIL: Mount namespace not isolated!"
	exit 1
fi
echo "PASS: Mount namespace isolated"
