#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login on a shell-less image: refused, and told the way in.
# Needs: 00-build.sh (scratch-test).

set -e

if sudo chroot-distro login scratch-test >/tmp/scratch-login.out 2>/tmp/scratch-login.err; then
	echo "FAIL: login entered a container whose image ships no shell"
	exit 1
fi
cat /tmp/scratch-login.err
grep -q "has no Entrypoint or Cmd defined" /tmp/scratch-login.err
echo "PASS: login refuses a shell-less image and names the reason"
