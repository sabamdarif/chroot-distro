#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Run every e2e suite in order, one bash process each, stopping at the first
# failure. The suites share runner state (installed containers, files under
# /tmp, a live httpd), so the order the prefixes give is the order they were
# written in and cannot be shuffled. cleanup.sh is not one of them: the workflow
# runs it separately so it also runs after a failure.

set -e

here=$(cd "$(dirname "$0")" && pwd)
# The suites resolve relative host paths against the repo root, which is where
# the runner starts every step.
cd "$here/../.."

for suite in "$here"/[0-9][0-9]-*/[0-9][0-9]-*.sh; do
	name=${suite#"$here"/}
	# GitHub folds each suite into a collapsible group named after its file; a
	# local run just sees the two marker lines.
	echo "::group::$name"
	if ! bash "$suite"; then
		echo "::endgroup::"
		echo "::error::$name failed"
		exit 1
	fi
	echo "::endgroup::"
done
