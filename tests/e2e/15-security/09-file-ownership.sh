#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify ownership of sudo-created files (finding #7)

set -e

# Report finding #7: a file created by container-root should not
# grant host root. Create one, then inspect it from the host.
data=$(sudo chroot-distro info 2>&1 | grep -m1 "Data location:" \
  | sed 's/.*Data location:[[:space:]]*//')
rootfs="$data/containers/debian-sec/rootfs"
echo "Container rootfs: $rootfs"
sudo chroot-distro login debian-sec --isolated -- sh -c 'touch /root/uidtest_ci'
owner=$(sudo stat -c '%u' "$rootfs/root/uidtest_ci")
echo "Host-side owner uid of the container-root-created file: $owner"
uid_map=$(sudo chroot-distro login debian-sec --isolated -- \
  sh -c 'tr -s " " < /proc/self/uid_map | sed "s/^ *//"')
base=$(echo "$uid_map" | awk '{print $2}')
count=$(echo "$uid_map" | awk '{print $3}')
echo "uid_map: '$uid_map'"
if [ -n "$count" ] && [ "$count" != "4294967295" ] && [ "$base" != "0" ]; then
	# Tier B (subordinate remap active): the file must be owned by
	# an unprivileged host uid, never real root.
	if [ "$owner" = "0" ]; then
		echo "FAIL: uid remap active but file still owned by host root (uid 0)"; exit 1
	fi
	echo "PASS: sudo-created file owned by unprivileged host uid $owner (finding #7 fixed)"
else
	# Tier A (identity userns) or Tier C: uid remap not active, so
	# the file is owned by host root. This is the documented state
	# until the Tier B idmapped-rootfs integration is enabled
	# (namespace._TIER_B_ROOTFS_IDMAP_READY). Capability scoping
	# (finding #3) is the active mitigation in this mode.
	echo "NOTE: uid remap not active (Tier A/C); file owned by uid $owner (expected)."
	echo "      Finding #7 is fully closed only under Tier B (idmapped rootfs)."
fi
