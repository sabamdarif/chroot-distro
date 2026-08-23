import contextlib
import os
import typing


class Stage:
    """Per-FROM state for the build engine.

    Holds descriptors on the stage's own scratch directory and on its
    rootfs, the rootfs path the stage works against, the evolving image
    config, the layers produced so far (each `{digest, size, diff_id}`
    in build order), and the per-stage scopes for ENV/ARG/USER/SHELL/
    WORKDIR that subsequent instructions inherit.

    The two descriptors are what every host-side step addresses the stage
    through; the path stays for what only a path can express (messages,
    bind sources). Both are None when the caller made the tree itself and
    has no scratch-root descriptor to create them from.
    """

    __slots__ = (
        "args",
        "declared_args",
        "dir_fd",
        "env",
        "image_config",
        "index",
        "layers",
        "name",
        "parent_layer_digest",
        "rootfs_dir",
        "rootfs_fd",
        "shell",
        "target_arch_pd",
        "user",
        "workdir",
    )

    def __init__(
        self,
        index: int,
        name: str,
        rootfs_dir: str,
        target_arch_pd: str,
        *,
        dir_fd: int | None = None,
        rootfs_fd: int | None = None,
    ):
        self.index = index
        self.name = name
        self.rootfs_dir = rootfs_dir
        self.dir_fd = dir_fd
        self.rootfs_fd = rootfs_fd
        self.image_config: dict[str, typing.Any] = {"config": {}}
        self.layers: list[dict[str, typing.Any]] = []
        self.parent_layer_digest = ""
        self.env: dict[str, str] = {}
        self.args: dict[str, str] = {}
        self.declared_args: set[str] = set()
        self.workdir = "/"
        self.user = ""
        self.shell = ["/bin/sh", "-c"]
        self.target_arch_pd = target_arch_pd

    def close(self) -> None:
        """Release the two descriptors. Idempotent."""
        for attr in ("rootfs_fd", "dir_fd"):
            fd = getattr(self, attr)
            setattr(self, attr, None)
            if fd is None:
                continue
            with contextlib.suppress(OSError):
                os.close(fd)
