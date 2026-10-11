#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify ownership of container-created files (finding #7)

set -e

# Report finding #7: a file created by container-root should not grant host
# root. Create one, then inspect it from the host.
data=$(sudo chroot-distro info 2>&1 | grep -m1 "Data location:" |
	sed 's/.*Data location:[[:space:]]*//')
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
	# Tier B (subordinate remap active, idmapped rootfs): the idmap is the
	# guest's own userns, so the write direction is honest by design: a file
	# created by container uid N lands on disk as uid N. The containment win
	# is the guest itself running as an unprivileged subordinate host uid.
	if [ "$owner" != "0" ]; then
		echo "FAIL: Tier B active but container-root's file is not uid 0 on disk (got $owner)"
		exit 1
	fi
	echo "PASS: Tier B: container-root file lands on disk as uid 0 (documented; the idmap cancels the userns translation)"

	# The containment property: the guest runs as the subordinate host uid.
	# /proc/<pid>/status read from the host shows the kernel uid, which must
	# match the uid_map base; reading it inside the namespace would only echo
	# the mapped view (uid 0).
	sudo chroot-distro login debian-sec --isolated -- sleep 2 >/dev/null 2>&1 &
	sleep 1
	host_uid=$(sudo sh -c 'for p in $(ls /proc | grep -E "^[0-9]+$"); do
		[ "$(cat /proc/$p/comm 2>/dev/null)" = sleep ] || continue
		awk "/^Uid:/ {print \$2; exit}" /proc/$p/status && break
	done' | head -n1)
	wait
	echo "Guest process kernel (host) uid: $host_uid"
	if [ -z "$host_uid" ]; then
		echo "FAIL: no guest process found to check the host uid"
		exit 1
	fi
	if [ "$host_uid" != "$base" ]; then
		echo "FAIL: guest host uid is $host_uid, want the map base $base"
		exit 1
	fi
	echo "PASS: guest runs as unprivileged host uid $host_uid (finding #7's containment half)"
else
	# Tier A (identity userns) or Tier C: uid remap not active, so the file
	# is owned by host root. Capability scoping (finding #3) is the active
	# mitigation in this mode.
	echo "NOTE: uid remap not active (Tier A/C); file owned by uid $owner (expected)."
	echo "      Tier B (idmapped rootfs) is unavailable on this kernel or run."
fi
