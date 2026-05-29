import json
import os
import sys

from chroot_distro.commands.login import command_login
from chroot_distro.message import crit_error
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_manifest, container_rootfs


def _read_image_config(container_name: str) -> dict:
    """Return the image_config.config dict from manifest.json, or {}."""
    manifest_path = container_manifest(container_name)
    try:
        with open(manifest_path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        crit_error(f"no image manifest found for container '{container_name}' "
                   f"which is required for command 'run'.")
        sys.exit(1)
    except (OSError, json.JSONDecodeError) as exc:
        crit_error(f"cannot read manifest.json for '{container_name}': {exc}")
        sys.exit(1)
    return data.get("image_config", {}).get("config") or {}


def command_run(args) -> None:
    """Execute the container image's Entrypoint/Cmd inside chroot."""
    container_name = args.container_name
    run_args = getattr(args, "run_args", []) or []

    require_valid_name(container_name)

    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    img_cfg = _read_image_config(container_name)

    entrypoint: list = list(img_cfg.get("Entrypoint") or [])
    cmd: list = list(img_cfg.get("Cmd") or [])

    if run_args:
        inner = entrypoint + run_args
    elif entrypoint or cmd:
        inner = entrypoint + cmd
    else:
        crit_error(f"the image manifest for '{container_name}' defines neither "
                   f"Entrypoint nor Cmd, and no command was given after "
                   f"'--'.")
        sys.exit(1)

    if not inner:
        crit_error(f"resolved command is empty for container "
                   f"'{container_name}'.")
        sys.exit(1)

    if not getattr(args, "work_dir", None):
        args.work_dir = img_cfg.get("WorkingDir") or "/"

    args._run_inner = inner
    args.login_cmd = []
    command_login(args)
