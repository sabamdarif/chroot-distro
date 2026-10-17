#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build contexts: COPY --from reads the named local context and the named image
# context, and FROM re-points through an image context.
# Needs: 00-context.sh (/tmp/bctx). Builds and installs the image.

set -eo pipefail

sudo chroot-distro build /tmp/bctx/ctx \
	-t test-build-context:latest \
	--install-as bctx-copy \
	--build-context assets=/tmp/bctx/assets \
	--build-context base=alpine:latest \
	--progress plain 2>&1 | tee /tmp/bctx/build.log

grep -q "Build complete" /tmp/bctx/build.log

# The image context named 'base' was pulled in place of a registry 'base'.
sudo chroot-distro run bctx-copy -- cat /etc/alpine-release >/dev/null

# The named local context's tree landed; its .dockerignore dropped the log.
test "$(sudo chroot-distro run bctx-copy -- cat /assets/marker.txt)" = "named-context-marker"
if sudo chroot-distro run bctx-copy -- test -e /assets/debug.log; then
	echo "FAIL: the named context's .dockerignore was not applied"
	exit 1
fi
echo "PASS: COPY --from read the named contexts and their .dockerignore"
