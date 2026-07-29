def __getattr__(name: str) -> str:
    # keeps importlib.metadata off the startup path.
    if name != "__version__":
        raise AttributeError(name)
    import importlib.metadata

    try:
        version = importlib.metadata.version("chroot-distro")
    except importlib.metadata.PackageNotFoundError:
        version = "rolling"
    globals()["__version__"] = version
    return version
