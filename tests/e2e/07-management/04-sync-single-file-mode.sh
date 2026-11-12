#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Sync and copy: single file mode and inode stamping
# Needs: 00-rename.sh (alpine-test).

set -e

echo "sync-mode-initial" >/tmp/sync-single-src.txt
chmod 0751 /tmp/sync-single-src.txt

sudo chroot-distro sync /tmp/sync-single-src.txt alpine-test:/tmp/sync-single-dst.txt
mode=$(sudo chroot-distro login alpine-test -- stat -c '%a' /tmp/sync-single-dst.txt)
[ "$mode" = "751" ] || {
	echo "FAIL: expected mode 751, got $mode"
	exit 1
}

echo "sync-mode-updated" >/tmp/sync-single-src.txt
chmod 0640 /tmp/sync-single-src.txt

# --checksum: both writes can land in one wall second, and the quick check
# compares whole-second mtimes, which would call the copy up to date.
sudo chroot-distro sync --checksum /tmp/sync-single-src.txt alpine-test:/tmp/sync-single-dst.txt
content=$(sudo chroot-distro login alpine-test -- cat /tmp/sync-single-dst.txt)
new_mode=$(sudo chroot-distro login alpine-test -- stat -c '%a' /tmp/sync-single-dst.txt)

[ "$content" = "sync-mode-updated" ] || {
	echo "FAIL: expected updated content, got $content"
	exit 1
}
[ "$new_mode" = "640" ] || {
	echo "FAIL: expected mode 640 after update, got $new_mode"
	exit 1
}

sudo chroot-distro copy /tmp/sync-single-src.txt alpine-test:/tmp/copy-single-dst.txt
copy_mode=$(sudo chroot-distro login alpine-test -- stat -c '%a' /tmp/copy-single-dst.txt)
[ "$copy_mode" = "640" ] || {
	echo "FAIL: copy expected mode 640, got $copy_mode"
	exit 1
}

rm -f /tmp/sync-single-src.txt
echo "PASS: sync and copy stamped the mode and content from the inode read"
