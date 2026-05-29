import importlib.metadata

try:
    __version__ = importlib.metadata.version("chroot-distro")
except importlib.metadata.PackageNotFoundError:
    __version__ = "rolling"
