#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (ADD url): a complete download lands in the image
# Needs: 00-start-server.sh; cleanup.sh stops the server.

set -eo pipefail

mkdir -p /tmp/add-build
cat > /tmp/add-build/Dockerfile << 'DOCKERFILE'
FROM alpine:latest
ADD http://127.0.0.1:8099/good /downloaded.txt
DOCKERFILE
sudo chroot-distro build /tmp/add-build -t test-build-add:latest \
  --progress plain --install-as test-build-add 2>&1 | tee /tmp/add-build.log
output=$(sudo chroot-distro login test-build-add -- cat /downloaded.txt)
echo "$output"
echo "$output" | grep -qx "downloaded-by-add"
echo "PASS: ADD over HTTP wrote the whole body"
