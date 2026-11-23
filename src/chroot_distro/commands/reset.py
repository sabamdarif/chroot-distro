# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro reset`: delete the rootfs and install the same image again.

Reset requires a registry tag in `manifest.json`. Validate the reference and
architecture before removing the rootfs, then call the registry install path
under the existing container name and lock.

Sessions and mounts are checked under an exclusive `ContainerLock` and a live one
aborts, rather than the rootfs going away under a running shell. Removal is
`remove.py`'s `_remove_path`; a tree it cannot finish is reported, swept once more
best-effort, and then installed over, because the install writes the same paths
again anyway.
"""

import contextlib
import json
import os
import shutil
import sys

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.arch import get_device_cpu_arch, normalize_arch
from chroot_distro.commands.install import _run_install
from chroot_distro.commands.remove import _remove_path
from chroot_distro.helpers.docker import InvalidReferenceError, parse_tag_reference
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_info, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_is_installed, container_manifest, container_rootfs


def command_reset(args) -> None:
    """Wipe the rootfs and reinstall from the cached image manifest."""
    container_name = args.container_name

    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    manifest_path = container_manifest(container_name)

    with ContainerLock(container_name, exclusive=True, command="reset"):
        if not container_is_installed(container_name):
            crit_error(f"container '{container_name}' is not installed.")
            sys.exit(1)

        manifest_data = None
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8") as fh:
                    manifest_data = json.load(fh)
            except (OSError, ValueError, RecursionError):
                pass
        if not isinstance(manifest_data, dict):
            manifest_data = {}
        raw_ref = manifest_data.get("image_ref")
        image_ref = raw_ref if isinstance(raw_ref, str) else ""
        try:
            parse_tag_reference(image_ref)
        except InvalidReferenceError:
            crit_error(f"container '{container_name}' has no valid registry tag for reset.")
            sys.exit(1)
        arch = manifest_data.get("arch")
        dist_arch: str | None
        if arch is None or arch == "":
            dist_arch = get_device_cpu_arch()
        else:
            dist_arch = normalize_arch(arch) if isinstance(arch, str) else None
            if dist_arch is None:
                crit_error(f"container '{container_name}' has an invalid architecture for reset.")
                sys.exit(1)

        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            crit_error(f"Cannot reset container '{container_name}': It has active sessions (PIDs: {active_pids}).")
            sys.exit(1)

        try:
            mount_manager.ensure_no_mounts(rootfs_dir)
        except Exception as e:
            crit_error(f"Failed mount safety check: {e}")
            sys.exit(1)

        log_info(f"Removing rootfs of '{container_name}'...")

        if not _remove_path(rootfs_dir):
            warn("Finished with errors. Some files could not be deleted. Proceeding anyway.")
            with contextlib.suppress(OSError):
                shutil.rmtree(rootfs_dir, ignore_errors=True)

        _run_install(container_name, image_ref, None, None, dist_arch)
