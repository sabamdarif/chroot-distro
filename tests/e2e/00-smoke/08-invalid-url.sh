#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Smoke: an invalid URL or term is reported as a message without a traceback

set -e

set +e
output=$(python3 -c '
import subprocess
p = subprocess.run(["chroot-distro", "search", "term\udcff"], capture_output=True, text=False)
print(p.stderr.decode("utf-8", "replace"), end="")
exit(p.returncode)
')
rc=$?
set -e

[ "$rc" -ne 0 ] || {
	echo "FAIL: invalid search term exited 0"
	exit 1
}
echo "$output" | grep -q "the search term is not valid text" || {
	echo "FAIL: expected invalid text message, got: $output"
	exit 1
}
if echo "$output" | grep -q "Traceback"; then
	echo "FAIL: failure output contained a traceback"
	exit 1
fi

echo "PASS: invalid search term was rejected cleanly without traceback"
