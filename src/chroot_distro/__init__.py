# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Package root, holding one thing: `__version__`, resolved only if it is asked for.

`importlib.metadata` is expensive to import and every command pays for whatever
this module does, so the version lookup lives in a module `__getattr__` and
caches into `globals()` on first access. An uninstalled tree (a git checkout run
in place) has no distribution metadata, which is not an error: the version reads
`"rolling"`.

Nothing else belongs here. A convenience re-export would put its whole import
tree on the startup path of every invocation.
"""


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
