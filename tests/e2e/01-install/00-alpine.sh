#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Phase 1: Install Containers
# Install: Alpine

set -e

sudo chroot-distro install alpine:latest
