#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Smoke: --json on the four reporting commands
#
# Runs before anything is installed, so every payload here is the empty one.
# What this holds is the envelope and the split between the streams: the
# document must parse from stdout alone, and a failure must still be a document.

set -e

# The document has to survive on its own: stderr carries the human lines.
check() {
	local command=$1
	shift
	sudo chroot-distro "$@" --json 2>/dev/null |
		python3 -c '
import json, sys

document = json.load(sys.stdin)
assert document["schema"] == 1, document
assert document["command"] == sys.argv[1], document
' "$command"
}

check list list
check ps ps
check info info

# A failure is a document too, and still exits non-zero.
set +e
output=$(sudo chroot-distro diff no-such-container --json 2>/dev/null)
status=$?
set -e
[ "$status" -ne 0 ] || {
	echo "diff on a missing container exited 0" >&2
	exit 1
}
printf '%s' "$output" | python3 -c '
import json, sys

document = json.load(sys.stdin)
assert document["schema"] == 1, document
assert document["command"] == "diff", document
assert "is not installed" in document["error"], document
'