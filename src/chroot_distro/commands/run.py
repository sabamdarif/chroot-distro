import json
import os
import sys

from chroot_distro.commands.login import command_login
from chroot_distro.commands.login.env import resolve_override as _resolve_override
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
        crit_error(f"no image manifest found for container '{container_name}' which is required for command 'run'.")
        sys.exit(1)
    except (OSError, json.JSONDecodeError) as exc:
        crit_error(f"cannot read manifest.json for '{container_name}': {exc}")
        sys.exit(1)
    return data.get("image_config", {}).get("config") or {}


def _normalize_argv(val) -> tuple[list, bool]:
    """Normalize an image Entrypoint/Cmd value into an argv list.

    Returns ``(argv, is_shell_form)``:
    - a JSON-array (exec form) becomes ``(list, False)``;
    - a non-empty string (shell form) becomes ``(["/bin/sh", "-c", val], True)``
      rather than being character-split by ``list()``;
    - anything else becomes ``([], False)``.
    """
    if isinstance(val, list):
        return [str(x) for x in val], False
    if isinstance(val, str) and val:
        return ["/bin/sh", "-c", val], True
    return [], False


def command_run(args) -> None:
    """Execute the container image's Entrypoint/Cmd inside chroot."""
    container_name = args.container_name
    run_args = getattr(args, "run_args", []) or []

    require_valid_name(container_name)

    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    # Resolve the override surface with precedence: CLI flag > CD_* env var >
    # image config default (applied further below). This must run before the
    # image-default fallbacks so the env vars can take effect.
    args.user = _resolve_override(getattr(args, "user", None), "CD_USER")
    args.work_dir = _resolve_override(getattr(args, "work_dir", None), "CD_WORKDIR")
    entrypoint_override = _resolve_override(getattr(args, "entrypoint", None), "CD_ENTRYPOINT")

    img_cfg = _read_image_config(container_name)

    image_ep, ep_is_shell = _normalize_argv(img_cfg.get("Entrypoint"))
    image_cmd, _ = _normalize_argv(img_cfg.get("Cmd"))

    if entrypoint_override is not None:
        # An explicit entrypoint replaces the image Entrypoint entirely and
        # clears Cmd (Docker semantics); trailing run args become its args.
        inner = [entrypoint_override, *run_args]
    elif run_args:
        # Trailing args replace Cmd, leaving the image Entrypoint intact.
        inner = image_ep + run_args
    elif ep_is_shell:
        # A shell-form Entrypoint embeds the whole command and ignores Cmd.
        inner = image_ep
    elif image_ep or image_cmd:
        inner = image_ep + image_cmd
    else:
        crit_error(
            f"the image manifest for '{container_name}' defines neither "
            f"Entrypoint nor Cmd, and no command was given after "
            f"'--'."
        )
        sys.exit(1)

    if not inner:
        crit_error(f"resolved command is empty for container '{container_name}'.")
        sys.exit(1)

    if not getattr(args, "work_dir", None):
        args.work_dir = img_cfg.get("WorkingDir") or "/"

    # Default to the image's User when no explicit --user (or CD_USER) was given.
    if getattr(args, "user", None) is None:
        img_user = img_cfg.get("User")
        if img_user:
            args.user = img_user

    args._run_inner = inner
    args.login_cmd = []
    command_login(args)
