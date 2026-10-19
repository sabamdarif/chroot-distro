#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build contexts refuse: a git source and a remote archive end the build
# naming the alternative, before anything is pulled or created.
# Needs: 00-context.sh (/tmp/bctx).

set -eo pipefail

if sudo sh -c 'chroot-distro build /tmp/bctx/ctx \
	-t test-build-context:latest \
	--build-context src=git+https://github.com/example/repo.git \
	--progress plain >/tmp/bctx/refuse-git.log 2>&1'; then
	echo "FAIL: a git build context was not refused"
	exit 1
fi
grep -q "no git client" /tmp/bctx/refuse-git.log
grep -q "archive" /tmp/bctx/refuse-git.log
echo "PASS: a git build context is refused naming the alternative"

if sudo sh -c 'chroot-distro build /tmp/bctx/ctx \
	-t test-build-context:latest \
	--build-context src=https://github.com/example/repo/archive/main.tar.gz \
	--progress plain >/tmp/bctx/refuse-url.log 2>&1'; then
	echo "FAIL: a remote-archive build context was not refused"
	exit 1
fi
grep -q "not a build context" /tmp/bctx/refuse-url.log
echo "PASS: a remote archive is refused as a build context"

# ADD from a git source is refused the same way, naming the alternative.
cat >/tmp/bctx/fromctx/Dockerfile.git <<'DOCKERFILE'
FROM alpine:latest
ADD git+https://github.com/example/repo.git /repo
DOCKERFILE
if sudo sh -c 'chroot-distro build /tmp/bctx/fromctx -f /tmp/bctx/fromctx/Dockerfile.git \
	-t test-build-context-git:latest \
	--progress plain >/tmp/bctx/refuse-add.log 2>&1'; then
	echo "FAIL: ADD from a git repository was not refused"
	exit 1
fi
grep -q "no git client" /tmp/bctx/refuse-add.log
echo "PASS: ADD from a git repository is refused naming the alternative"
