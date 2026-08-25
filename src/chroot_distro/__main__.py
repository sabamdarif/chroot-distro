# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`python -m chroot_distro`, for a checkout with no console script installed.

The installed entry point goes straight to `cli.main`; this is the same door for
`uv run python -m chroot_distro` and for a `pip install -e .` tree.
"""

from chroot_distro.cli import main

if __name__ == "__main__":
    main()
