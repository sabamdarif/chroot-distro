# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`.dockerignore` loading and matching, on Docker's own rules.

A line is cleaned the way Docker cleans one: a `#` at the start is a comment
before any trimming, whitespace goes, a `!` inverts, the rest is normalised as a
path and a leading `/` dropped, so `/build` and `build` are one pattern. The
cleaned pattern compiles to a regex the way Docker's own matcher compiles one:
`*` and `?` stop at a `/`, `**` spans any number of segments, and a `[...]` class
is passed through.

That separator rule is the whole reason this is not `fnmatch`, whose `*` crosses
`/`: `*.log` ignored `docs/a.log` and `src/*` ignored `src/a/b`, which is a file
quietly missing from the image, the one failure direction this module exists to
avoid.

`is_ignored` is Docker's MatchesOrParentMatches: the last pattern to match
decides, and a match on any parent directory counts, so naming a directory
covers everything under it. That parent rule is what lets `copy_step`'s walk
enter an ignored directory anyway, since a `!` line re-including one of its
children only survives if the walk goes in.

A missing file means no patterns, and an unreadable one warns and also means no
patterns: ignoring nothing copies too much, which the user can see, where
ignoring everything would quietly produce an image missing its files. A pattern
that will not compile is dropped the same way, for the same reason.
`Dockerfile` and `.dockerignore` are never ignored, matching Docker.
"""

import functools
import glob as _glob
import logging
import os
import posixpath
import re

log = logging.getLogger(__name__)

_BOM = "\ufeff"

# Regex metacharacters with no meaning in a path pattern, which Docker escapes
# on its way to a regex. `*`, `?`, `\`, `[` and `]` are handled by the walk
# below instead, and every other character reaches the regex as it was written,
# so a `[a-z]` range still means one.
_ESCAPE = frozenset(".+()|{}$")


def load_dockerignore(build_dir: str) -> list[str]:
    """Return the cleaned `.dockerignore` patterns from *build_dir*."""
    path = os.path.join(build_dir, ".dockerignore")
    patterns: list[str] = []
    try:
        with open(path) as fh:
            for lineno, line in enumerate(fh):
                raw = line.rstrip("\n").rstrip("\r")
                if lineno == 0:
                    raw = raw.removeprefix(_BOM)
                # A comment is a `#` in the first column, as Docker reads one:
                # an indented `#` is a pattern for a file whose name starts with
                # it.
                if raw.startswith("#"):
                    continue
                cleaned = clean_pattern(raw)
                if cleaned:
                    patterns.append(cleaned)
    except FileNotFoundError as exc:
        log.debug("No .dockerignore found at %s: %s", path, exc)
    except OSError as exc:
        log.warning("Failed to load .dockerignore at %s: %s", path, exc)
    return patterns


def clean_pattern(raw: str) -> str:
    """One `.dockerignore` line, normalised. Empty when the line says nothing.

    The `!` is stripped before the path is normalised and put back after, so an
    exclusion is cleaned like any other pattern. A bare `!` names nothing and is
    dropped rather than failing the build over a line that cannot re-include
    anything.
    """
    pattern = raw.strip()
    negate = pattern.startswith("!")
    if negate:
        pattern = pattern[1:].strip()
    if not pattern:
        return ""
    pattern = _clean_path(pattern)
    return "!" + pattern if negate else pattern


def _clean_path(pattern: str) -> str:
    """A pattern's path part, normalised: separators, `.` segments, leading `/`.

    Applied again where a pattern is compiled, not only where a line is read: a
    caller composing one itself gets the same rules as a `.dockerignore` line,
    rather than a pattern that silently matches nothing.
    """
    pattern = posixpath.normpath(pattern.replace(os.sep, "/"))
    if len(pattern) > 1 and pattern.startswith("/"):
        pattern = pattern[1:]
    return pattern


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """Return True iff *rel_path* matches the loaded ignore patterns.

    Docker's rule, and the order is the whole of it: the last pattern to match
    wins, an inclusion is only consulted while the path is not ignored yet and an
    exclusion only while it is, and a pattern that matches any parent directory
    matches the path itself.
    """
    if not patterns:
        return False
    rel = posixpath.normpath(rel_path.replace(os.sep, "/").lstrip("/"))
    # Docker's builder sends both whatever the patterns say, since a context
    # without them cannot be built at all.
    if rel in ("Dockerfile", ".dockerignore"):
        return False
    if rel in (".", "/", ""):
        return False
    ancestors = _ancestors(rel)
    ignored = False
    for pat in patterns:
        negate = pat.startswith("!")
        # An inclusion adds nothing to an already ignored path, and an exclusion
        # takes nothing off one that is not ignored.
        if negate != ignored:
            continue
        regex = _compiled(pat[1:] if negate else pat)
        if regex is None:
            continue
        if regex.match(rel) or any(regex.match(parent) for parent in ancestors):
            ignored = not negate
    return ignored


def _ancestors(rel: str) -> tuple[str, ...]:
    """Every directory *rel* sits under, shallowest first."""
    parts = rel.split("/")[:-1]
    return tuple("/".join(parts[: i + 1]) for i in range(len(parts)))


@functools.lru_cache(maxsize=1024)
def _compiled(pattern: str) -> re.Pattern[str] | None:
    """The regex *pattern* matches paths with, or None when it cannot compile.

    Cached because one `.dockerignore` is applied to every entry of a tree, and
    the pattern set of a build is a handful of short strings.
    """
    source = _translate(_clean_path(pattern))
    try:
        return re.compile(source)
    except re.error as exc:
        log.warning("Ignoring .dockerignore pattern %r: %s", pattern, exc)
        return None


def _translate(pattern: str) -> str:
    r"""Docker's pattern-to-regex translation, with `/` as the separator.

    `\Z` rather than `$` for the end: a name may hold a trailing newline, which
    `$` would match before.
    """
    out = ["^"]
    i = 0
    end = len(pattern)
    while i < end:
        ch = pattern[i]
        i += 1
        if ch == "*" and i < end and pattern[i] == "*":
            i += 1
            # `**/` is `**`, so the separator belongs to the wildcard.
            if i < end and pattern[i] == "/":
                i += 1
            # Trailing, it covers the rest of the path; otherwise it stands for
            # any number of leading segments, none included.
            out.append(".*" if i >= end else "(.*/)?")
        elif ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "\\":
            # The next character is a literal. A trailing backslash is one.
            if i < end:
                out.append(re.escape(pattern[i]))
                i += 1
            else:
                out.append("\\\\")
        elif ch in _ESCAPE:
            out.append("\\" + ch)
        else:
            out.append(ch)
    out.append(r"\Z")
    return "".join(out)


def simple_glob(base: str, pattern: str) -> list[str]:
    """Tiny glob: supports * and ? only (no ** recursion). Returns rel paths."""
    abs_pat = os.path.join(base, pattern)
    matches = _glob.glob(abs_pat)
    return [os.path.relpath(p, base) for p in matches]
