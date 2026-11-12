# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The container-name rule and the diagnostic for a rejected name.

Callers must validate names from command arguments and backup archives before
using them as components of runtime paths.
"""

import re

from chroot_distro.exceptions import InvalidNameError

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*\Z")

NAME_RULE_HINT = "It must begin with a letter or digit and contain only letters, digits, underscores, dots, or hyphens."


def is_valid_name(name: str) -> bool:
    """Return True iff *name* satisfies the container-name regex."""
    return bool(_NAME_RE.match(name or ""))


def require_valid_name(name: str, kind: str = "container name") -> None:
    """Raise InvalidNameError when *name* is invalid."""
    if not is_valid_name(name):
        raise InvalidNameError(f"{kind} {name!a} is not valid. {NAME_RULE_HINT}")
