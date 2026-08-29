#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (ADD url): start a server that lies about Content-Length

set -e

here=$(cd "$(dirname "$0")" && pwd)

nohup python3 "$here/lying-server.py" > /tmp/lying-server.log 2>&1 &
for i in $(seq 1 20); do
	if curl -sf http://127.0.0.1:8099/good | grep -q "downloaded-by-add"; then
		echo "server answering on attempt $i"
		break
	fi
	sleep 1
done
curl -sf http://127.0.0.1:8099/good | grep -q "downloaded-by-add"
echo "PASS: server up"
