# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The container-name rule, in one place, with the hint the error message uses.

A name reaches the filesystem as a directory component under the data and cache
roots, so it is validated before anything is built from it, `restore` included:
an archive names a container, and this is what keeps that name from naming a path.
"""

import re

from chroot_distro.exceptions import InvalidNameError

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*\Z")

NAME_RULE_HINT = "It must begin with a letter or digit and contain only letters, digits, underscores, dots, or hyphens."


def is_valid_name(name: str) -> bool:
    """Return True iff *name* satisfies the container-name regex."""
    return bool(_NAME_RE.match(name or ""))


def require_valid_name(name: str, kind: str = "container name") -> None:
    """Raise InvalidNameError when *name* is invalid; otherwise return None."""
    if not is_valid_name(name):
        raise InvalidNameError(f"{kind} '{name}' is not valid. {NAME_RULE_HINT}")
