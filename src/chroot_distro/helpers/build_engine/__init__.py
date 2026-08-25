# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The build engine's surface, re-exported for `commands/build.py`.

Everything else in the package is internal to the engine, so a new name here
means a new caller outside it.
"""

from chroot_distro.helpers.build_engine.constants import (
    CHROOT_REQUIRED_INSTRUCTIONS,
    needs_chroot,
)
from chroot_distro.helpers.build_engine.engine import BuildEngine
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.stage import Stage

__all__ = (
    "CHROOT_REQUIRED_INSTRUCTIONS",
    "BuildEngine",
    "BuildError",
    "Stage",
    "needs_chroot",
)
