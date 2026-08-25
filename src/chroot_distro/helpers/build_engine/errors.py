# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The exception that ends a build.

Distinct from `exceptions.BuildError`, and deliberately not a
`ChrootDistroError`: `commands/build.py` catches this one itself and prints it
as a build failure, rather than letting `cli.main` report it as a program error.
Its message is interpolated from names the Dockerfile's author did not
necessarily write (a member of an ADD'd archive, an entry of a base image), so
whoever prints one quotes it.
"""


class BuildError(Exception):
    """Raised by handlers when the build cannot proceed."""
