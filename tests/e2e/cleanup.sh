#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Everything the suite leaves on the runner, removed. The workflow runs this
# under `if: always()`, which is why the two cleanups that used to sit mid-suite
# are here: a script in a loop cannot run after an earlier failure, and nothing
# between them and the end of the job reads the host account, the /tmp/chown-*
# files or port 8099.

set -e

echo "=== Removing the host account 08-chown/07-host-side.sh created ==="
sudo userdel hostonly 2>/dev/null || true
# /tmp is sticky, and chown-host.txt now belongs to uid 4321,
# so the runner's own account can no longer unlink it.
sudo rm -rf /tmp/chown-src.txt /tmp/chown-host.txt /tmp/chown-tree

echo "=== Killing all sessions ==="
sudo chroot-distro kill httpd 2>/dev/null || true
pkill -f lying-server.py 2>/dev/null || true
echo "=== Unmounting all containers ==="
for name in httpd debian alpine alpine-test test-build test-build-adv \
            test-build-out test-build-out2 test-build-add debian-sec; do
	sudo chroot-distro unmount "$name" 2>/dev/null || true
done
echo "=== Removing all containers ==="
for name in httpd debian alpine alpine-test test-build test-build-adv \
            test-build-out test-build-out2 test-build-add debian-sec; do
	sudo chroot-distro remove "$name" 2>/dev/null || true
done
echo "=== Final state ==="
sudo chroot-distro list
echo "=== Cleanup complete ==="

output=$(sudo chroot-distro list -q 2>&1)
echo "Remaining containers: '$output'"
