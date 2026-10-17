#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build contexts: a main context, a named local one, and a base image to
# re-point through a named image context.
#
# The named local context carries a marker the verification reads out of the
# built image, plus a file its own .dockerignore drops so the ignore rules the
# context ships are checked too. The Dockerfile names the image context in a
# COPY --from and the local one in a FROM, so both kinds are exercised.

set -e

rm -rf /tmp/bctx
mkdir -p /tmp/bctx/ctx /tmp/bctx/assets /tmp/bctx/standalone

echo "context-file" >/tmp/bctx/ctx/app.txt
cat >/tmp/bctx/ctx/Dockerfile <<'DOCKERFILE'
FROM base
COPY --from=assets . /assets/
DOCKERFILE

echo "named-context-marker" >/tmp/bctx/assets/marker.txt
echo "noise" >/tmp/bctx/assets/debug.log
printf '*.log\n' >/tmp/bctx/assets/.dockerignore

echo "standalone-file" >/tmp/bctx/standalone/standalone.txt

echo "--- Dockerfile ---"
cat /tmp/bctx/ctx/Dockerfile
