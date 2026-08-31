# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""One request in, one platform's image out: the boundary around a single solve.

`BuildRequest` says what to build, `PlatformResult` is what came out, and
`solve_platform` is the only thing between them. Everything an engine run mutates
is made here and dropped here: the scratch tree the stages are assembled in, the
stage map, the global ARG scope, the reporter's step numbering. A second request
therefore starts from nothing the first one left behind, and a failed one leaves
nothing for the next.

A request is read, never written, which is what lets two of them share one parse
of the Dockerfile: no handler mutates an instruction, and a request for another
platform is this one with `target_platform` replaced.

What a solve produces does not live in its scratch tree. A layer is published
into the layer cache under the digest of its own bytes, and the manifest and the
config are documents in memory, so the tree goes as soon as the engine is closed,
whether the build succeeded or not.
"""

import contextlib
import dataclasses
import os
import typing

from chroot_distro import dirfd
from chroot_distro.arch import Platform
from chroot_distro.helpers.build_engine.engine import BuildEngine
from chroot_distro.helpers.build_engine.events import make_reporter
from chroot_distro.helpers.oci_writer import build_manifest_and_config


@dataclasses.dataclass(frozen=True)
class BuildRequest:
    """What one solve is asked for: the context, the options, two platforms.

    `scratch_dir` and `scratch_fd` are the build's own scratch root and a
    descriptor on it, which is where the solve makes its tree; the rest are
    validated command-line values. One target platform per request, so a matrix
    is one request per platform rather than one request that fans out.
    """

    build_dir: str
    instructions: list[dict[str, typing.Any]]
    target_platform: Platform
    build_platform: Platform
    scratch_dir: str
    scratch_fd: int
    user_build_args: dict[str, str] = dataclasses.field(default_factory=dict)
    target_stage: str | None = None
    verbose: bool = False
    quiet: bool = False
    no_cache: bool = False
    emulator: str = ""
    isolation_mode: str = "none"
    secrets: dict[str, str] = dataclasses.field(default_factory=dict)
    ssh_sockets: dict[str, str] = dataclasses.field(default_factory=dict)
    progress: str = "auto"


@dataclasses.dataclass(frozen=True)
class PlatformResult:
    """One solve's finished image: the platform it is for, and its documents.

    Self-contained by the time a caller holds one: the scratch tree is gone, the
    layers name blobs in the layer cache, and the two documents are the bytes to
    publish.
    """

    platform: Platform
    manifest: dict[str, typing.Any]
    image_config: dict[str, typing.Any]
    layers: list[dict[str, typing.Any]]


def solve_platform(request: BuildRequest) -> PlatformResult:
    """Build *request*'s one target platform and return what it produced.

    A `BuildError` is the build failing, and an `OSError` is one of the engine's
    walks losing its footing; both reach the caller, which is what decides
    whether anything else still runs.
    """
    name, tmp_root, tmp_root_fd = _make_solve_tmp(request)
    engine: BuildEngine | None = None
    try:
        engine = BuildEngine(
            build_dir=request.build_dir,
            tmp_root=tmp_root,
            target_arch_pd=request.target_platform.to_arch(),
            user_build_args=request.user_build_args,
            target_stage=request.target_stage,
            verbose=request.verbose,
            quiet=request.quiet,
            no_cache=request.no_cache,
            emulator=request.emulator,
            isolation_mode=request.isolation_mode,
            secrets=request.secrets,
            ssh_sockets=request.ssh_sockets,
            reporter=make_reporter(request.progress, request.quiet),
            tmp_root_fd=tmp_root_fd,
            target_platform=request.target_platform,
            build_platform=request.build_platform,
        )
        stage = engine.run(request.instructions)
        manifest, image_config = build_manifest_and_config(
            stage.image_config,
            stage.layers,
            request.target_platform.architecture,
        )
        return PlatformResult(
            platform=request.target_platform,
            manifest=manifest,
            image_config=image_config,
            layers=list(stage.layers),
        )
    finally:
        # The stage descriptors point inside the tree about to be removed, and
        # this solve's own root descriptor is what they were made off.
        if engine is not None:
            engine.close()
        with contextlib.suppress(OSError):
            os.close(tmp_root_fd)
        dirfd.rmtree_at(request.scratch_fd, name, force=True, on_error=lambda _rel, _exc: None)


def _make_solve_tmp(request: BuildRequest) -> tuple[str, str, int]:
    """Create this solve's scratch tree: (name, path, a descriptor on it).

    Made with mkdirat off the build's scratch-root descriptor, so the walk that
    validated the root is not repeated and nothing made below it needs one
    either: the root is 0700 and this name is fresh. Fresh rather than `solve-0`
    because `run_step` derives a step's holder key from the basename, and that
    key has to stay unique among concurrent builds.

    The name comes back so the removal can name it under the same descriptor
    instead of resolving the path a second time.
    """
    name = f"solve-{os.getpid()}.{os.urandom(4).hex()}"
    os.mkdir(name, 0o700, dir_fd=request.scratch_fd)
    return name, os.path.join(request.scratch_dir, name), dirfd.opendir_at(request.scratch_fd, name)
