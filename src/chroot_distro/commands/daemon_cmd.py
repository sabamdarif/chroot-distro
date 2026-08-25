# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro daemon`: the init system's entry point into `daemon.serve`.

Not a command a user runs. `commands/setup.py` writes it into the service unit,
and `cli.main` exempts it from elevation because the init system already starts
it as root. Everything it does is in `daemon.py`.
"""

import argparse

from chroot_distro.daemon import serve


def command_daemon(args: argparse.Namespace) -> None:
    """Run the group-gated privileged daemon (started by the init system)."""
    serve(persist=bool(getattr(args, "persist", False)))
