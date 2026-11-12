#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): copying a directory over an existing regular file is refused

set -e

mkdir -p /tmp/diroverfile-build/mydir
echo "nested" >/tmp/diroverfile-build/mydir/nested.txt

cat >/tmp/diroverfile-build/Dockerfile <<-'EOF'
FROM alpine:latest
COPY mydir /etc/issue
EOF

set +e
sudo sh -c 'chroot-distro build /tmp/diroverfile-build -t test-diroverfile:latest \
	--progress plain >/tmp/diroverfile-build.log 2>&1'
rc=$?
set -e

cat /tmp/diroverfile-build.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: copying a directory over a regular file was accepted"
	exit 1
}

grep -qF "Failed to write 'etc/issue/nested.txt' into rootfs: 'etc/issue' is not a directory inside it" /tmp/diroverfile-build.log || {
	echo "FAIL: missing refusal message when copying directory over file"
	exit 1
}

if grep -q "Traceback" /tmp/diroverfile-build.log; then
	echo "FAIL: build failure dumped a traceback"
	exit 1
fi

echo "PASS: copying directory over regular file refused cleanly"
