# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The middle layer: policy and orchestration between `commands/` and `syscalls/`.

A marker module only, deliberately empty of code. Importing a helper here to
shorten a call site would pull that helper's import tree into every command that
touches the package, and startup latency is a design constraint.
"""
