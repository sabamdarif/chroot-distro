#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: httpd serving in detached mode

set -e

success=false
for i in $(seq 1 30); do
	if curl -s http://localhost/ 2>/dev/null | grep -q "It works!"; then
		echo "httpd is serving in detached mode on attempt $i!"
		success=true
		break
	fi
	sleep 2
done

if [ "$success" = false ]; then
	echo "FAIL: httpd did not start serving in detached mode"
	exit 1
fi

response=$(curl -s http://localhost/)
echo "$response"
echo "$response" | grep -q "It works!"
echo "PASS: httpd serves in detached mode"
