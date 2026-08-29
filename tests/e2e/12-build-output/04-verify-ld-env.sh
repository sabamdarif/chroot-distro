#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (output): the Dockerfile's LD_* never reached a RUN step
# Needs: 02-build.sh (/tmp/out-build.log), 03-verify-archives.sh (/tmp/oci-report.txt).

set -e

run() { sudo chroot-distro login test-build-out -- "$@"; }

# The claim is about provenance, not about the variable being
# unset: what the Dockerfile said must not be what the step saw.
# (The runner's own environment sets LD_LIBRARY_PATH, and a value
# the invoking user chose is theirs to pass.)
lib=$(run cat /ld-library-path.txt)
audit=$(run cat /ld-audit.txt)
echo "LD_LIBRARY_PATH seen by the step: $lib"
echo "LD_AUDIT seen by the step: $audit"
[ "$lib" != "lib" ] \
  || { echo "FAIL: the ENV line's value reached the RUN step"; exit 1; }
[ "$audit" != "./audit-passed.so" ] \
  || { echo "FAIL: the --build-arg value reached the RUN step"; exit 1; }
echo "PASS: neither the ENV line nor the --build-arg value was in the step env"

run cat /app-mode.txt | grep -qx "prod"
echo "PASS: an ordinary ENV still reaches the step"

grep -qF "ignoring 'LD_LIBRARY_PATH' for RUN steps" /tmp/out-build.log
grep -qF "ignoring 'LD_AUDIT' for RUN steps" /tmp/out-build.log
echo "PASS: the build said what it dropped"

# Refused for the exec, kept in the image: what the Dockerfile
# says about the image it produces is its author's business.
grep -qx "env LD_LIBRARY_PATH=lib" /tmp/oci-report.txt
grep -qx "env APP_MODE=prod" /tmp/oci-report.txt
echo "PASS: both ENV lines stand in the image config"
