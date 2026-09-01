#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Local cache: the specs this program will not honour.
# Needs: 00-context.sh (/tmp/cache-build), 01-export.sh (/tmp/cache-dir).
#
# Both refusals happen before the solve, so neither leaves a tag, an archive or a
# container behind, and the folder 01-export.sh wrote is still the one 03-import.sh
# reads.

set -e

if sudo chroot-distro build /tmp/cache-build -t test-build-cache:latest \
	--cache-from type=registry,ref=docker.io/example/cache 2> /tmp/cache-registry.err; then
	echo "FAIL: a registry cache was accepted"
	exit 1
fi
cat /tmp/cache-registry.err
grep -q "type=local" /tmp/cache-registry.err
echo "PASS: only type=local is accepted"

mkdir -p /tmp/not-a-cache
echo "not an index" > /tmp/not-a-cache/build-cache.json
if sudo chroot-distro build /tmp/cache-build -t test-build-cache:latest \
	--cache-from type=local,src=/tmp/not-a-cache 2> /tmp/cache-bad.err; then
	echo "FAIL: a folder that is not a cache folder was accepted"
	exit 1
fi
cat /tmp/cache-bad.err
grep -q "build-cache.json" /tmp/cache-bad.err
echo "PASS: a folder that is there and is not one ends the build"

test -r /tmp/cache-dir/build-cache.json
