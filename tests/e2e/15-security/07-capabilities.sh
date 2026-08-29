#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Security: Verify capability confinement under sudo (finding #3)

set -e

# Report finding #3: container root must NOT wield host-level
# capabilities. Determine the active tier from uid_map, then
# assert the appropriate confinement.
uid_map=$(sudo chroot-distro login debian-sec --isolated -- \
  sh -c 'tr -s " " < /proc/self/uid_map | sed "s/^ *//"')
count=$(echo "$uid_map" | awk '{print $3}')
echo "uid_map: '$uid_map'"
if [ -n "$count" ] && [ "$count" != "4294967295" ]; then
	# User namespace active: capabilities are namespace-scoped.
	# A privileged op that needs real (init-userns) CAP_SYS_ADMIN
	# (mounting a fresh sysfs) must be denied even though the
	# in-namespace CapEff looks full.
	res=$(sudo chroot-distro login debian-sec --isolated -- sh -c \
    'mkdir -p /tmp/capchk; if mount -t sysfs sysfs /tmp/capchk 2>/dev/null; then \
       umount /tmp/capchk 2>/dev/null; echo RESULT=ALLOWED; else echo RESULT=DENIED; fi')
	echo "$res"
	if echo "$res" | grep -q "RESULT=ALLOWED"; then
		echo "FAIL: init-privileged mount succeeded, capabilities NOT confined"; exit 1
	fi
	echo "PASS: host-level capability denied, capabilities are namespace-scoped"
else
	# No user namespace: the cap-drop fallback must have removed
	# the dangerous caps from the bounding set (not the full set).
	out=$(sudo chroot-distro login debian-sec --isolated -- \
    sh -c 'grep CapBnd /proc/self/status')
	echo "$out"
	cap_bnd=$(echo "$out" | awk '{print $2}')
	if [ "$cap_bnd" = "000001ffffffffff" ]; then
		echo "FAIL: full capability bounding set, neither user namespace nor cap-drop active"; exit 1
	fi
	echo "PASS: capability bounding set restricted (cap-drop fallback)"
fi
