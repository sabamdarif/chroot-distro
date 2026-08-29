#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 8c: Build Outputs, ADD over HTTP, Failure Paths
# Covers what 8b does not reach: `--output` archives (packed into
# the descriptor the staging helper created, so the published file
# has to be a complete OCI image), the host-loader env vars a
# Dockerfile may not hand a RUN step, an `--install-as` name that is
# already taken, an ADD whose response ends short of the length it
# declared, and what a failed build prints.
# Build (output): create the build context

set -e

mkdir -p /tmp/out-build/ctx-tree/sub
echo "context-file" > /tmp/out-build/ctx-tree/sub/f.txt
cat > /tmp/out-build/Dockerfile << 'DOCKERFILE'
FROM alpine:latest
ARG LD_AUDIT=./audit-default.so
ENV LD_LIBRARY_PATH=lib
ENV APP_MODE=prod

# A rw bind is a scratch copy the step may do as it likes
# with, sealed directories and a tree deeper than the host's
# recursion limit included; the teardown after the step still
# has to get the copy out.
RUN --mount=type=bind,source=ctx-tree,target=/ctx,rw <<'EOF'
set -e
test -f /ctx/sub/f.txt
mkdir -p /ctx/sealed/inner
chmod 000 /ctx/sealed
cd /ctx
i=0
# One character per level: the shell tracks its cwd as a string
# and 1200 levels of a longer name run past PATH_MAX.
while [ "$i" -lt 1200 ]; do
    mkdir d
    cd d
    i=$((i + 1))
done
EOF

# LD_* is read by the host's loader when `chroot` is exec'd, so
# neither an ENV line nor a declared ARG's value may reach a RUN
# step. Both must be missing from the step's environment.
RUN printenv LD_LIBRARY_PATH > /ld-library-path.txt || echo refused > /ld-library-path.txt
RUN printenv LD_AUDIT > /ld-audit.txt || echo refused > /ld-audit.txt
RUN printenv APP_MODE > /app-mode.txt
CMD ["/bin/sh"]
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/out-build/Dockerfile
