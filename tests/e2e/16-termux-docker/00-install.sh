#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 11: Termux-rooted Guest
# The only image in the suite whose filesystem is rooted at the Termux prefix
# instead of /, so the only one taking the dist_type == "termux" branch: no /bin
# or /usr, sh and bash under $PREFIX/bin, /etc/passwd an absolute symlink into
# /system/etc, and /system a relative symlink to a bundled AOSP bionic linker.
# The install-time Termux fixup (register_android_ids) is IS_TERMUX-gated, so it
# stays uncovered here; everything else in that branch does not.
# Install: termux/termux-docker
# The tag is latest, a real manifest list, so the platform is picked the normal
# way. The arch-suffixed tags are single-manifest aliases and would pin one.

set -e

sudo chroot-distro install termux/termux-docker:latest
