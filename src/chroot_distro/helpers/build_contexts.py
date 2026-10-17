# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Named build contexts: the `name=VALUE` table `--build-context` builds.

A name a Dockerfile's FROM or a `COPY --from=name` uses resolves through this
table before it is read as a stage name or an image reference. Two value kinds
exist, and both lean on fetchers that already exist rather than adding one:

- a local directory: COPY reads it the way it reads the main build context,
  with that directory's own `.dockerignore`; FROM names it by standing the
  stage up from `scratch` and copying the tree in, which is how Docker
  answers the same line.
- an OCI image reference: FROM pulls it the way it pulls any other base, and
  `COPY --from=` pulls it into a throwaway tree.

An http(s) tarball is refused by name: ADD already fetches one, so the only
shape it could take here is as a context value, and Docker does not read
those either. A git source is refused by name too, naming the alternative
(parsing.refuse_git_message owns the wording, since ADD shares it): there is
no git protocol client in the stdlib, and a checkout passed as a local
directory context covers the same ground. Neither refusal is silent, because
a value read as an image reference instead would fail on a pull of a name
that never existed.

Which kind a value is lands as late as the resolver, not here: `os.path.isdir`
answers it, because a path that exists is the directory the user named and a
path that does not is an image reference, which is also how a typo'd path
surfaces (a pull failure naming the value, not a silent miss).
"""

import os
import re

from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.parsing import looks_like_git, looks_like_url, refuse_git_message

# Lowercased keys of the context table that cannot be taken over, so the name
# a Dockerfile uses to refer to the main context keeps its meaning. Docker
# reserves it for the same reason.
RESERVED_CONTEXT_NAMES = frozenset({"dockerfile"})

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def parse_build_contexts(raw: list[str]) -> dict[str, str]:
    """Parse repeatable `name=VALUE` items into {lowercased name: value}.

    Name validation mirrors Docker's: letters, digits and the punctuation a
    stage name carries, lowercased so FROM and `COPY --from=` match it
    case-insensitively the way Docker matches one. The kind of a value is
    decided here and the decision is final: a URL or a git-shaped value is
    refused outright, so what reaches the engine is only ever a directory or
    an image reference.
    """
    contexts: dict[str, str] = {}
    for item in raw:
        name, sep, value = item.partition("=")
        if not sep or not name.strip() or not value.strip():
            raise BuildError(f"invalid --build-context '{item}' (expected name=VALUE).")
        key = name.strip().lower()
        if key in RESERVED_CONTEXT_NAMES:
            raise BuildError(f"--build-context name '{name.strip()}' is reserved.")
        if not _NAME_RE.match(key):
            raise BuildError(
                f"--build-context name '{name.strip()}' is not valid; "
                "use letters, digits, '.', '_' or '-', starting with a letter or digit."
            )
        value = value.strip()
        if looks_like_git(value):
            raise BuildError(f"--build-context {key}: {refuse_git_message(value)}")
        if looks_like_url(value):
            raise BuildError(
                f"--build-context {key}={value}: a remote archive is not a build context here; "
                "download it, unpack it, and pass the directory instead."
            )
        contexts[key] = value
    return contexts


def resolve_context_dir(value: str) -> str:
    """The absolute path of a local-directory context value.

    The command resolves the value once, before the locks, so the engine and
    COPY read the same directory even if the build later changes directory.
    A value that names no directory is an image reference and stays as given.
    """
    resolved = os.path.abspath(os.path.expanduser(value))
    return resolved if os.path.isdir(resolved) else value
