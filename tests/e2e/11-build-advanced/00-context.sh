#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 8b: Advanced Build Test
# A realistic multi-stage build exercising ARG, ENV, WORKDIR,
# USER, heredoc RUN, COPY --parents, COPY --from,
# RUN --mount=type=cache/tmpfs/secret, and --build-arg/--secret
# on the CLI. The result is verified by running commands inside
# the built container, and a rebuild checks layer caching plus
# cache-mount persistence across builds.
# Build (advanced): create multi-stage build context

set -e

mkdir -p /tmp/adv-build/app/src/lib /tmp/adv-build/config
cat > /tmp/adv-build/app/src/main.sh << 'SH'
#!/bin/sh
. /opt/app/bin/src/lib/util.sh
greet
SH
cat > /tmp/adv-build/app/src/lib/util.sh << 'SH'
greet() { echo "hello from util"; }
SH
echo "loglevel=debug" > /tmp/adv-build/config/app.conf
echo "s3cr3t-api-key-do-not-bake" > /tmp/adv-secret.txt
cat > /tmp/adv-build/Dockerfile << 'DOCKERFILE'
ARG ALPINE_TAG=latest

FROM alpine:${ALPINE_TAG} AS builder
ARG APP_VERSION=unset
ENV BUILD_DIR=/build
WORKDIR ${BUILD_DIR}

# keep src/ structure relative to the /./ pivot
COPY --parents ./app/./src/main.sh ./app/./src/lib/util.sh /build/

RUN --mount=type=cache,target=/var/cache/adv \
    --mount=type=tmpfs,target=/scratch <<'EOF'
set -e
echo probe > /scratch/probe
test -f /scratch/probe
if [ -f /var/cache/adv/marker ]; then
    echo "cache-hit" > /build/cachemount.txt
else
    echo "cache-miss" > /build/cachemount.txt
    echo populated > /var/cache/adv/marker
fi
printf 'version=%s\n' "$APP_VERSION" > /build/version.txt
chmod +x /build/src/main.sh
EOF

# secret is available during build but must not be baked in
RUN --mount=type=secret,id=apikey \
    test -s /run/secrets/apikey && \
    sha256sum /run/secrets/apikey | cut -d' ' -f1 > /build/secret.sha

FROM alpine:${ALPINE_TAG}
LABEL org.test.suite="chroot-distro-e2e"
ENV APP_HOME=/opt/app
WORKDIR ${APP_HOME}

COPY --from=builder /build/src/ ${APP_HOME}/bin/src/
COPY --from=builder /build/version.txt /build/cachemount.txt /build/secret.sha ${APP_HOME}/
COPY config/app.conf /etc/app/app.conf

RUN adduser -D -u 1234 appuser && chown -R appuser:appuser ${APP_HOME}
USER appuser
RUN whoami > ${APP_HOME}/built-by.txt
CMD ["/opt/app/bin/src/main.sh"]
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/adv-build/Dockerfile
