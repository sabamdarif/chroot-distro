#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Multi-platform build: the context for a mixed build/target Dockerfile.
#
# One builder stage pinned to the build platform, one target stage that only
# assembles files, which is the shape that needs no emulator: the RUN always
# runs on the host's own CPU, and the foreign image is written rather than
# executed. The report the builder writes carries the automatic platform ARGs of
# whichever solve produced it, so a later step can read back what each of the
# two platforms was told it was building for.

set -e

mkdir -p /tmp/multi-build
cat > /tmp/multi-build/Dockerfile << 'DOCKERFILE'
FROM --platform=$BUILDPLATFORM alpine:latest AS builder
ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETVARIANT
ARG BUILDPLATFORM
ARG BUILDARCH
RUN <<'EOF'
set -e
mkdir -p /out
{
    echo "target=$TARGETPLATFORM"
    echo "targetarch=$TARGETARCH"
    echo "targetvariant=$TARGETVARIANT"
    echo "build=$BUILDPLATFORM"
    echo "buildarch=$BUILDARCH"
    echo "ran-on=$(uname -m)"
} > /out/report
EOF

FROM alpine:latest
LABEL org.test.suite="chroot-distro-e2e"
COPY --from=builder /out/report /report
CMD ["cat", "/report"]
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/multi-build/Dockerfile
