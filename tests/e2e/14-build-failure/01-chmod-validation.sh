#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): --chmod validates octal range before applying

set -e

mkdir -p /tmp/chmod-build
echo "payload" >/tmp/chmod-build/file.txt

for invalid_mode in "999" "u+x" "77777"; do
	cat >/tmp/chmod-build/Dockerfile <<-EOF
	FROM alpine:latest
	COPY --chmod=$invalid_mode file.txt /file.txt
	EOF

	set +e
	sudo sh -c 'chroot-distro build /tmp/chmod-build -t test-chmod:latest \
		--progress plain >/tmp/chmod-build.log 2>&1'
	rc=$?
	set -e

	[ "$rc" -ne 0 ] || {
		echo "FAIL: invalid --chmod=$invalid_mode did not fail the build"
		exit 1
	}

	grep -qF "Invalid COPY --chmod value '$invalid_mode'" /tmp/chmod-build.log || {
		echo "FAIL: missing validation error for --chmod=$invalid_mode"
		exit 1
	}
	grep -qF "octal string between 0 and 07777" /tmp/chmod-build.log || {
		echo "FAIL: missing octal range advice for --chmod=$invalid_mode"
		exit 1
	}
	if grep -q "Traceback" /tmp/chmod-build.log; then
		echo "FAIL: build failure dumped a traceback"
		exit 1
	fi
done

cat >/tmp/chmod-build/Dockerfile <<-'EOF'
FROM alpine:latest
COPY --chmod=0755 file.txt /file.txt
EOF

sudo chroot-distro build /tmp/chmod-build -t test-chmod:latest \
	--progress plain --install-as test-chmod
mode=$(sudo chroot-distro login test-chmod -- stat -c '%a' /file.txt)
[ "$mode" = "755" ] || {
	echo "FAIL: expected mode 755, got $mode"
	exit 1
}

sudo chroot-distro unmount test-chmod || true
sudo chroot-distro remove test-chmod || true
echo "PASS: --chmod validated invalid octal modes and applied valid mode"
