#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): an unusable URL in ADD is reported as a message without a traceback

set -e

mkdir -p /tmp/badurl-build
cat >/tmp/badurl-build/Dockerfile <<-'EOF'
FROM alpine:latest
ADD http://[ /badurl.txt
EOF

set +e
sudo sh -c 'chroot-distro build /tmp/badurl-build -t test-badurl:latest \
	--progress plain >/tmp/badurl.log 2>&1'
rc=$?
set -e

cat /tmp/badurl.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: an unusable URL in ADD was accepted"
	exit 1
}

grep -qF "ADD http://[: 'http://[' is not a valid URL" /tmp/badurl.log || {
	echo "FAIL: missing invalid URL refusal message"
	exit 1
}

if grep -q "Traceback" /tmp/badurl.log; then
	echo "FAIL: build failure dumped a traceback"
	exit 1
fi

echo "PASS: unusable URL in ADD was refused with an error and no traceback"
