# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The exception tree, whose only job is to mark a failure as expected.

During dispatch, `cli.main` reports a `ChrootDistroError` with its message and
exits with status 1. A command that accepted `--json` also gets an error
document. Other dispatch exceptions get an "unexpected error" prefix, with
dedicated handling for unsupported operations and interrupts.
"""


class ChrootDistroError(Exception):
    """Base class for all chroot-distro exceptions."""


class ContainerNotFoundError(ChrootDistroError):
    """Raised when a container cannot be found."""


class MountError(ChrootDistroError):
    """Raised when mounting/unmounting mounts fails."""


class MountRefusedError(MountError):
    """Raised when a guest path cannot be resolved to a safe mount target.

    A symlink or non-directory standing where a mount point must be means the
    operation is refused rather than followed: the rootfs is untrusted input,
    and following the link is the escape it is asking for.
    """


class LockConflictError(ChrootDistroError):
    """Raised when a command cannot acquire a lock."""


class InvalidNameError(ChrootDistroError):
    """Raised when a container name fails validation."""


class RootRequiredError(ChrootDistroError):
    """Raised when required privileges cannot be obtained."""


class BuildError(ChrootDistroError):
    """Raised during container image builds."""
