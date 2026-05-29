import contextlib
import json
import os
import shutil
import sys
from types import SimpleNamespace

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.commands.install import command_install
from chroot_distro.commands.remove import _remove_path
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_error, log_info
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_manifest, container_rootfs


def command_reset(args) -> None:
    """Wipe the rootfs and reinstall from the cached image manifest."""
    container_name = args.container_name

    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    manifest_path = container_manifest(container_name)

    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    image_ref = None
    override_arch = None
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path) as fh:
                manifest_data = json.load(fh)
            image_ref = manifest_data.get("image_ref")
            override_arch = manifest_data.get("arch")
        except (OSError, json.JSONDecodeError):
            pass

    if not image_ref:
        crit_error(f"container '{container_name}' has no OCI "
                   f"manifest. Reset is supported for OCI images only.")
        sys.exit(1)

    with ContainerLock(container_name, exclusive=True, command="reset"):
        # 1. Active sessions check
        active_pids = session.get_active_chroot_pids(container_name)
        if active_pids:
            crit_error(f"Cannot reset container '{container_name}': It has active sessions (PIDs: {active_pids}).")
            sys.exit(1)

        # 2. Mount safety check
        try:
            mount_manager.ensure_no_mounts(rootfs_dir)
        except Exception as e:
            crit_error(f"Failed mount safety check: {e}")
            sys.exit(1)

        log_info(f"Removing rootfs of '{container_name}'...")

        if not _remove_path(rootfs_dir):
            log_error("Finished with errors. Some files could not be deleted. Proceeding anyway.")
            with contextlib.suppress(OSError):
                shutil.rmtree(rootfs_dir, ignore_errors=True)

        command_install(
            SimpleNamespace(
                image_ref=image_ref,
                custom_container_name=container_name,
                override_arch=override_arch,
            )
        )
