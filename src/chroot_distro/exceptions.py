# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The exception tree, whose only job is to mark a failure as expected.

`cli.main` catches `ChrootDistroError` and turns it into one line plus exit code 1, so
raising a subclass is how a command reports a condition a user can act on. Anything
else escapes as an "unexpected error", which is the traceback path. Each class carries
no state: the message is the whole payload.
"""


class ChrootDistroError(Exception):
    """Base class for all chroot-distro exceptions."""


class ContainerNotFoundError(ChrootDistroError):
    """Raised when a container cannot be found."""


class MountError(ChrootDistroError):
    """Raised when mounting/unmounting mounts fails."""


class LockConflictError(ChrootDistroError):
    """Raised when a file/container lock is already held by another process."""


class InvalidNameError(ChrootDistroError):
    """Raised when a container name fails validation."""


class RootRequiredError(ChrootDistroError):
    """Raised when an operation requires root privileges but run by unprivileged user."""


class BuildError(ChrootDistroError):
    """Raised during container image builds."""
