class ChrootDistroError(Exception):
    """Base class for all chroot-distro exceptions."""


class ContainerNotFoundError(ChrootDistroError):
    """Raised when a container cannot be found."""


class ContainerExistsError(ChrootDistroError):
    """Raised when trying to create a container that already exists."""


class UnsupportedArchError(ChrootDistroError):
    """Raised when an architecture is not supported by the system or container."""


class DownloadError(ChrootDistroError):
    """Raised when downloading a resource fails."""


class ExtractionError(ChrootDistroError):
    """Raised when extracting a rootfs/tarball fails."""


class MountError(ChrootDistroError):
    """Raised when mounting/unmounting mounts fails."""


class LockConflictError(ChrootDistroError):
    """Raised when a file/container lock is already held by another process."""


class InvalidNameError(ChrootDistroError):
    """Raised when a container name fails validation."""


class RootRequiredError(ChrootDistroError):
    """Raised when an operation requires root privileges but run by unprivileged user."""


class RegistryError(ChrootDistroError):
    """Raised during OCI registry interactions."""


class BuildError(ChrootDistroError):
    """Raised during container image builds."""
