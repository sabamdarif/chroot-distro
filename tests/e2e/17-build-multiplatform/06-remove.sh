#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Remove: the multi-platform containers and the archive

set -e

sudo chroot-distro remove test-build-multi
sudo chroot-distro remove test-build-multi-arm
sudo rm -f /tmp/multi-build.oci.tar
