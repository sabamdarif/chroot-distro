#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): a Dockerfile exceeding the 16 MiB ceiling is refused

set -e

mkdir -p /tmp/ceiling-build
python3 -c '
with open("/tmp/ceiling-build/Dockerfile", "wb") as f:
	f.write(b"FROM alpine:latest\n# " + b"x" * (16 * 1024 * 1024) + b"\n")
'

set +e
sudo sh -c 'chroot-distro build /tmp/ceiling-build -t test-ceiling:latest \
	--progress plain >/tmp/ceiling-file.log 2>&1'
rc=$?
set -e

[ "$rc" -ne 0 ] || {
	echo "FAIL: a Dockerfile exceeding 16 MiB was accepted"
	exit 1
}

grep -qF "Dockerfile is larger than 16777216 bytes; refusing to read it." /tmp/ceiling-file.log || {
	echo "FAIL: missing 16 MiB ceiling refusal message"
	exit 1
}

if grep -q "Traceback" /tmp/ceiling-file.log; then
	echo "FAIL: file ceiling failure dumped a traceback"
	exit 1
fi

set +e
sudo sh -c 'cat /tmp/ceiling-build/Dockerfile | chroot-distro build /tmp/ceiling-build \
	-f - -t test-ceiling:latest --progress plain >/tmp/ceiling-stdin.log 2>&1'
rc=$?
set -e

[ "$rc" -ne 0 ] || {
	echo "FAIL: stdin Dockerfile exceeding 16 MiB was accepted"
	exit 1
}

grep -qF "Dockerfile is larger than 16777216 bytes; refusing to read it." /tmp/ceiling-stdin.log || {
	echo "FAIL: missing stdin 16 MiB ceiling refusal message"
	exit 1
}

if grep -q "Traceback" /tmp/ceiling-stdin.log; then
	echo "FAIL: stdin ceiling failure dumped a traceback"
	exit 1
fi

echo "PASS: Dockerfile ceiling of 16 MiB enforced on file and stdin"
