#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Registry: start mock registry server for e2e tests

set -e

here=$(cd "$(dirname "$0")" && pwd)

nohup python3 "$here/mock-registry.py" >/tmp/mock-registry.log 2>&1 &

for i in $(seq 1 20); do
	if curl -sf --max-time 5 http://127.0.0.1:8097/health | grep -q "OK"; then
		echo "mock registry answering on attempt $i"
		break
	fi
	sleep 1
done

curl -sf --max-time 5 http://127.0.0.1:8097/health | grep -q "OK"
echo "PASS: mock registry started"
