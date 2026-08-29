#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: the host side answers for a host destination
# Needs: cleanup.sh removes the host account this creates.

set -e

sudo useradd -u 4321 -M -s /usr/sbin/nologin hostonly
# The container knows no 'hostonly', so a guest-side lookup
# would fail here instead of succeeding with the host's id.
if sudo chroot-distro login alpine-test -- id hostonly >/dev/null 2>&1; then
	echo "FAIL: the container knows 'hostonly', so this proves nothing"; exit 1
fi
sudo chroot-distro copy alpine-test:/etc/hostname /tmp/chown-host.txt --chown hostonly
owner=$(stat -c '%u' /tmp/chown-host.txt)
echo "host-side owner uid: $owner"
[ "$owner" = "4321" ] || { echo "FAIL: expected 4321, got $owner"; exit 1; }
echo "PASS: a host destination was resolved against the host passwd"
