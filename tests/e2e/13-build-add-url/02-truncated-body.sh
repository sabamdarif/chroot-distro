#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (ADD url): a body that ends early fails the build
# Needs: 00-start-server.sh; cleanup.sh stops the server.

set -e

mkdir -p /tmp/short-build
cat > /tmp/short-build/Dockerfile << 'DOCKERFILE'
FROM alpine:latest
ADD http://127.0.0.1:8099/short /truncated.bin
DOCKERFILE
set +e
sudo chroot-distro build /tmp/short-build -t test-build-short:latest \
  --progress plain --install-as test-build-short > /tmp/short-build.log 2>&1
rc=$?
set -e
cat /tmp/short-build.log
[ "$rc" -ne 0 ] || { echo "FAIL: a truncated download was accepted as the file"; exit 1; }
grep -qF "the response ended after 4096 of 1048576 bytes" /tmp/short-build.log
if grep -q "Traceback" /tmp/short-build.log; then
	echo "FAIL: the failure left the program as a traceback"; exit 1
fi
if sudo chroot-distro list -q 2>&1 | grep -q "test-build-short"; then
	echo "FAIL: the failed build still installed a container"; exit 1
fi
echo "PASS: the short body failed the build, cleanly and with nothing installed"
