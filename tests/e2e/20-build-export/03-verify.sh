#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build export verify: the tarball and the directory hold the built rootfs.
# Needs: 01-build.sh (/tmp/export.tar and /tmp/export-dir).

set -eo pipefail

# The directory holds the marker the RUN wrote, at the root with no wrapper.
grep -q "chroot-distro-export-test" /tmp/export-dir/export-marker.txt
test -f /tmp/export-dir/etc/alpine-release
echo "PASS: the directory export is the rootfs"

# The tarball lists the same marker at its root, and no OCI layout beside it.
sudo tar -tf /tmp/export.tar | tee /tmp/export-list.txt >/dev/null
grep -qx "export-marker.txt" /tmp/export-list.txt
if grep -q "oci-layout\|index.json\|manifest.json" /tmp/export-list.txt; then
	echo "FAIL: the tarball carries OCI layout documents"
	exit 1
fi
echo "PASS: the tarball is a plain rootfs, not an OCI archive"

# Both exports carry the same content.
diff /tmp/export-dir/export-marker.txt <(sudo tar -xOf /tmp/export.tar export-marker.txt)
echo "PASS: the tarball and the directory agree"
