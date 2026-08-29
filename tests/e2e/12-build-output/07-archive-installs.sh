#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (output): the archive installs as a container of its own
# Needs: 02-build.sh (/tmp/out-build.tar).

set -e

sudo chroot-distro install /tmp/out-build.tar --name test-build-out2
output=$(sudo chroot-distro login test-build-out2 -- cat /app-mode.txt)
echo "$output"
echo "$output" | grep -qx "prod"
# The bind was torn down before the layer was snapshotted, so
# what the step wrote through it is not in the published image.
if sudo chroot-distro login test-build-out2 -- test -e /ctx/sub/f.txt; then
	echo "FAIL: the rw bind's contents were committed to the image"; exit 1
fi
echo "PASS: the published archive round-trips through install"
