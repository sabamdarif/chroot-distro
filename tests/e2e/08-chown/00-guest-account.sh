#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 7b: --chown on copy and sync
# The flag resolves a name on the side the files land on, so these
# steps need a real account that exists in the container and not on
# the host (and one the other way round). uid 1500 with primary
# group 1600 is deliberately mismatched: a resolver that used the
# uid as the gid would still pass a 1500:1500 check.
# Chown: create a guest account with a distinct primary group

set -e

sudo chroot-distro login alpine-test -- addgroup -g 1600 appgrp
sudo chroot-distro login alpine-test -- adduser -D -u 1500 -G appgrp appuser
ids=$(sudo chroot-distro login alpine-test -- sh -c 'printf "%s:%s" "$(id -u appuser)" "$(id -g appuser)"')
echo "appuser ids: $ids"
[ "$ids" = "1500:1600" ] || { echo "FAIL: expected 1500:1600, got $ids"; exit 1; }
echo "PASS: guest account ready"
