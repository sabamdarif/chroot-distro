import typing


class Stage:
    """Per-FROM state for the build engine.

    Holds the rootfs path the stage works against, the evolving image
    config, the layers produced so far (each `{digest, size, diff_id}`
    in build order), and the per-stage scopes for ENV/ARG/USER/SHELL/
    WORKDIR that subsequent instructions inherit.
    """

    __slots__ = (
        "args",
        "declared_args",
        "env",
        "image_config",
        "index",
        "layers",
        "name",
        "parent_layer_digest",
        "rootfs_dir",
        "shell",
        "target_arch_pd",
        "user",
        "workdir",
    )

    def __init__(self, index: int, name: str, rootfs_dir: str, target_arch_pd: str):
        self.index = index
        self.name = name
        self.rootfs_dir = rootfs_dir
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
