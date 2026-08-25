# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""ICD and loader descriptors for the open Mesa stack (AMD, Intel and friends).

The device nodes arrive on their own, through the default `/dev` bind, so the
only thing missing is metadata: a Vulkan, EGL/GLVND or OpenCL loader enumerates
hardware by reading ICD descriptor files, and a container image that ships none
sees no GPU even with `/dev/dri` in place. `find_gpu_icd_binds` names the host
directories and files holding those descriptors, to be bound read-only at the
same paths.

A path that already exists inside the rootfs is skipped, so an image with its own
Mesa stack keeps its own descriptors: the host's are a fallback, never an
override. `helpers/nvidia.py` covers the proprietary driver.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

# Host directories and files holding GPU ICD / loader configuration.
# Directories are bound whole; individual files are bound when present.
_GPU_ICD_PATHS = (
    "/usr/share/vulkan/icd.d",
    "/usr/share/vulkan/implicit_layer.d",
    "/usr/share/vulkan/explicit_layer.d",
    "/usr/share/glvnd/egl_vendor.d",
    "/usr/share/egl/egl_external_platform.d",
    "/usr/share/gbm",
    "/etc/OpenCL/vendors",
    "/etc/drirc",
    "/usr/share/drirc.d",
)


def find_gpu_icd_binds(rootfs: str) -> list[tuple[str, str]]:
    """Return ``(host_path, guest_path)`` pairs for GPU ICD/loader config.

    Only host paths that exist are returned. Paths already present inside
    the rootfs are skipped so the container's own descriptors win.
    Guest paths mirror the host paths.
    """
    binds: list[tuple[str, str]] = []
    for path in _GPU_ICD_PATHS:
        if not os.path.exists(path):
            continue
        guest_abs = os.path.join(rootfs, path.lstrip("/"))
        if os.path.exists(guest_abs):
            continue
        binds.append((path, path))
    if binds:
        log.debug("GPU ICD integration: %d config path(s) bound read-only", len(binds))
    return binds
