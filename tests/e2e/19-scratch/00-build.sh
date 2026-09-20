#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Scratch: an image built from no base distribution at all.
#
# FROM scratch pulls nothing, so this suite needs no network at all: the rootfs
# ends up holding one copied file, no shell and no /etc. That is the shape the
# report used to call a broken install, and the shape login refuses with a
# pointer to run. Container: scratch-test

set -e

rm -rf /tmp/scratch-build
mkdir -p /tmp/scratch-build
echo "chroot-distro-scratch-test" >/tmp/scratch-build/hello.txt
cat >/tmp/scratch-build/Dockerfile <<'DOCKERFILE'
FROM scratch
COPY hello.txt /hello.txt
DOCKERFILE
echo "--- Dockerfile ---"
cat /tmp/scratch-build/Dockerfile

sudo chroot-distro build /tmp/scratch-build -t scratch-test:latest --install-as scratch-test
