#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (output): the scratch root left nothing behind

set -e

data=$(sudo chroot-distro info 2>&1 | grep -m1 "Data location:" \
  | sed 's/.*Data location:[[:space:]]*//')
echo "Data location: $data"
sudo test -d "$data/build-tmp" || { echo "FAIL: no build-tmp; the build fell back to /tmp"; exit 1; }
left=$(sudo ls -A "$data/build-tmp" | wc -l)
if [ "$left" -ne 0 ]; then
	sudo ls -lA "$data/build-tmp"
	echo "FAIL: $left entries survived the build, sealed rw-bind copy included"
	exit 1
fi
echo "PASS: build-tmp is empty"
