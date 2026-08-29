#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (advanced): run built container
# Needs: 01-build.sh, and /tmp/adv-secret.txt for the host-side sha.

set -e

run() { sudo chroot-distro login test-build-adv -- "$@"; }

out=$(run /opt/app/bin/src/main.sh)
echo "main.sh output: $out"
echo "$out" | grep -q "hello from util"
echo "PASS: COPY --parents structure + heredoc chmod + COPY --from work"

run cat /opt/app/version.txt | grep -qx "version=2.5.1"
echo "PASS: --build-arg reached RUN env"

run cat /opt/app/cachemount.txt | grep -qx "cache-miss"
echo "PASS: first build saw an empty cache mount"

run cat /etc/app/app.conf | grep -qx "loglevel=debug"
echo "PASS: plain COPY from context works"

run cat /opt/app/built-by.txt | grep -qx "appuser"
echo "PASS: USER applied to subsequent RUN"

want=$(sha256sum /tmp/adv-secret.txt | cut -d' ' -f1)
got=$(run cat /opt/app/secret.sha)
[ "$got" = "$want" ]
echo "PASS: secret was mounted during build"

if run test -e /run/secrets/apikey; then
	echo "FAIL: secret baked into image"; exit 1
fi
if run test -e /build; then
	echo "FAIL: builder stage leaked into final image"; exit 1
fi
echo "PASS: no secret or builder-stage files in final image"
