#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): an untrusted name in an error is escaped

set -e

# The name a failed build reports on is not always the author's (a
# member of an ADD'd archive, an entry of a base image), and one
# holding ESC repaints the terminal it is printed to.
mkdir -p /tmp/escape-build
printf 'FROM alpine:latest\nCOPY nope\033file.txt /nope.txt\n' \
  > /tmp/escape-build/Dockerfile
cat -v /tmp/escape-build/Dockerfile
set +e
sudo chroot-distro build /tmp/escape-build -t test-build-escape:latest \
  --progress plain > /tmp/escape-build.log 2>&1
rc=$?
set -e
cat -v /tmp/escape-build.log
[ "$rc" -ne 0 ] || { echo "FAIL: a missing COPY source did not fail the build"; exit 1; }
# The progress log echoes the Dockerfile's own lines, which is
# the author's text; the assertion is about the error line, whose
# name may just as well have come out of an image.
grep -F "Build failed" /tmp/escape-build.log > /tmp/escape-failline.txt \
  || { echo "FAIL: the build printed no failure line"; exit 1; }
cat -v /tmp/escape-failline.txt
grep -qF 'nope\efile.txt' /tmp/escape-failline.txt \
  || { echo "FAIL: the reported name was not escaped"; exit 1; }
if grep -qF "$(printf 'nope\033file.txt')" /tmp/escape-failline.txt; then
	echo "FAIL: a raw escape reached the terminal"; exit 1
fi
[ "$(wc -l < /tmp/escape-failline.txt)" -eq 1 ] \
  || { echo "FAIL: the failure was not one line"; exit 1; }
if grep -q "Traceback" /tmp/escape-build.log; then
	echo "FAIL: the failure left the program as a traceback"; exit 1
fi
echo "PASS: the name was printed escaped and the build failed cleanly"
