#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Install: a downloaded archive ending before declared Content-Length fails
# Needs: 00-start-server.sh (lying-server.py on port 8099).

set -e

set +e
sudo sh -c 'chroot-distro install http://127.0.0.1:8099/short \
	-n test-truncated-install >/tmp/short-install.log 2>&1'
rc=$?
set -e

cat /tmp/short-install.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: a truncated download was accepted as a complete rootfs"
	exit 1
}

grep -qF "the response ended after 4096 of 1048576 bytes" /tmp/short-install.log || {
	echo "FAIL: missing truncated body error message"
	exit 1
}

if grep -q "Traceback" /tmp/short-install.log; then
	echo "FAIL: truncated download failed with a traceback"
	exit 1
fi

if sudo chroot-distro list -q 2>&1 | grep -q "test-truncated-install"; then
	echo "FAIL: the failed install left a container registered"
	exit 1
fi

echo "PASS: truncated archive download failed cleanly with nothing installed"
