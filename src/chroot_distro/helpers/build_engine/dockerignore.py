# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`.dockerignore` loading and matching.

Approximate on purpose, and the approximation is written down rather than
worked around: `**` collapses to `*`, and a pattern prefix-matches, so naming a
directory covers everything under it. That prefix rule is what lets
`copy_step`'s walk enter an ignored directory anyway, since a `!` line
re-including one of its children only survives if the walk goes in.

A missing file means no patterns, and an unreadable one warns and also means no
patterns: ignoring nothing copies too much, which the user can see, where
ignoring everything would quietly produce an image missing its files.
`Dockerfile` and `.dockerignore` are never ignored, matching Docker.
"""

import fnmatch
import glob as _glob
import logging
import os

log = logging.getLogger(__name__)


def load_dockerignore(build_dir: str) -> list[str]:
    """Return the list of `.dockerignore` patterns from *build_dir*."""
    path = os.path.join(build_dir, ".dockerignore")
    patterns = []
    try:
        with open(path) as fh:
            for line in fh:
                s = line.rstrip("\n").rstrip("\r").strip()
                if not s or s.startswith("#"):
                    continue
                patterns.append(s)
    except FileNotFoundError as exc:
        log.debug("No .dockerignore found at %s: %s", path, exc)
    except OSError as exc:
        log.warning("Failed to load .dockerignore at %s: %s", path, exc)
    return patterns


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """Return True iff *rel_path* matches the loaded ignore patterns."""
    if not patterns:
        return False
    # `Dockerfile` and `.dockerignore` themselves are never ignored.
    if rel_path in ("Dockerfile", ".dockerignore"):
        return False
    ignored = False
    for pat in patterns:
        negate = pat.startswith("!")
        p = pat[1:] if negate else pat
        if _match(rel_path, p):
            ignored = not negate
    return ignored


def _match(rel_path: str, pattern: str) -> bool:
    pat = pattern.replace(os.sep, "/").strip("/")
    rel = rel_path.replace(os.sep, "/").strip("/")
    if "**" in pat:
        pat = pat.replace("**", "*")
    if fnmatch.fnmatchcase(rel, pat):
        return True
    # Prefix match: a pattern like `node_modules` ignores its children.
    parts = rel.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        if fnmatch.fnmatchcase(prefix, pat):
            return True
    return False


def simple_glob(base: str, pattern: str) -> list[str]:
    """Tiny glob: supports * and ? only (no ** recursion). Returns rel paths."""
    abs_pat = os.path.join(base, pattern)
    matches = _glob.glob(abs_pat)
    return [os.path.relpath(p, base) for p in matches]
