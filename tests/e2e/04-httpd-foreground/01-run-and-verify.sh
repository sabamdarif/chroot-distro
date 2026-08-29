#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Run: httpd foreground (backgrounded) and verify
# Needs: 00-install.sh. The backgrounded httpd is meant to outlive this
# script, so never wait on it here: 02-kill.sh is what stops it.

set -e

sudo chroot-distro run httpd &
HTTPD_PID=$!
echo "httpd launched (shell PID: $HTTPD_PID), waiting for it to start..."

# Poll until httpd responds or timeout after 60 seconds
success=false
for i in $(seq 1 30); do
	if curl -s http://localhost/ 2>/dev/null | grep -q "It works!"; then
		echo "httpd is serving on attempt $i!"
		success=true
		break
	fi
	sleep 2
done

if [ "$success" = false ]; then
	echo "FAIL: httpd did not start serving within 60 seconds"
	curl -v http://localhost/ 2>&1 || true
	exit 1
fi

# Final assertion on response content
response=$(curl -s http://localhost/)
echo "--- httpd response ---"
echo "$response"
echo "--- end response ---"
echo "$response" | grep -q "It works!"
echo "PASS: httpd serves the default page"
