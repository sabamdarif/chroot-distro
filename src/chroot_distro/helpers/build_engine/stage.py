# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The per-FROM state a build carries from one instruction to the next.

One `Stage` per FROM, and the only thing an instruction handler mutates: the
engine keeps the list, `copy_step` reads another stage's rootfs out of it for
`COPY --from`, and `layer_diff` packs from its descriptors. The class docstring
says what the fields hold.

`close()` releases the two descriptors. The engine closes every stage it
registered, and a stage that fails while its base is being set up closes itself,
since the engine's list does not know about it yet.
"""

import contextlib
import os
import typing

from chroot_distro.arch import Platform, platform_from_arch


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
        "base_image_ref",
        "base_manifest_digest",
        "declared_args",
        "dir_fd",
        "env",
        "image_config",
        "index",
        "layers",
        "name",
        "parent_layer_digest",
        "platform",
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
        platform: Platform | None = None,
    ):
        self.index = index
        self.name = name
        self.base_image_ref = ""
        self.base_manifest_digest = ""
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
        self.platform = platform or platform_from_arch(target_arch_pd)
        self.target_arch_pd = self.platform.to_arch()

    def close(self) -> None:
        """Release the two descriptors. Idempotent."""
        for attr in ("rootfs_fd", "dir_fd"):
            fd = getattr(self, attr)
            setattr(self, attr, None)
            if fd is None:
                continue
            with contextlib.suppress(OSError):
                os.close(fd)
