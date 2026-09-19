#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify: an image with no base distribution is described, not flagged.
# Needs: 00-build.sh (scratch-test).

set -e

host_arch=$(uname -m)
output=$(sudo chroot-distro info 2>&1)
echo "$output"

row=$(echo "$output" | grep -E "^[[:space:]]+scratch-test[[:space:]]")
echo "$row"
# Nothing in the rootfs answers the ELF probe, since its candidates are all
# shells, so the manifest's own arch is the only answer: "unknown" means
# nothing answered at all.
echo "$row" | grep -qw "$host_arch"

# The analysis section lists a container as "  <name>:", the same shape the
# detail block below the table uses, and its heading carries colour codes, so
# nothing here anchors on a row: the finding that used to be raised for this
# image is the check that it is not flagged.
if echo "$output" | grep -q "no recognizable rootfs layout"; then
	echo "FAIL: a scratch image was reported as a broken install"
	exit 1
fi

# The image has no shell and no Entrypoint or Cmd, so the report says both.
echo "$output" | grep -q "Shell:"
echo "$output" | grep -q "no Entrypoint or Cmd"
echo "PASS: scratch-test is listed with the manifest's arch and no finding"
