#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Chown: an unknown name is refused before anything is written
# Needs: 01-copy-in-container.sh (/tmp/chown-src.txt).

set -e

if sudo chroot-distro copy /tmp/chown-src.txt alpine-test:/tmp/chown-never.txt --chown ghost; then
	echo "FAIL: an unknown name was accepted"; exit 1
fi
if sudo chroot-distro login alpine-test -- test -e /tmp/chown-never.txt; then
	echo "FAIL: the destination was written despite the error"; exit 1
fi
echo "PASS: a typo fails the command instead of handing the files to root"
