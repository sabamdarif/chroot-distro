import sys
import typing
import urllib.error

from chroot_distro.arch import get_device_cpu_arch, normalize_arch
from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.helpers.docker import (
    load_manifest_cache,
    parse_image_ref,
    push_image,
)
from chroot_distro.locking import BuildLock
from chroot_distro.message import C, crit_error, log_error, log_info, msg
from chroot_distro.progress import fmt_size


def command_push(args: typing.Any) -> None:
    """Implements `chroot-distro push`."""
    image_ref = getattr(args, "image_ref", None) or ""
    override_arch = getattr(args, "override_arch", None) or ""
    quiet = bool(getattr(args, "quiet", False))

    if not image_ref:
        crit_error("image reference is not specified (e.g. 'myrepo/myapp:1.0').")
        sys.exit(1)

    # Append :latest the same way build does, so users can push using the
    # short form even when they tagged the build with the implicit tag.
    last = image_ref.split("/")[-1]
    if ":" not in last:
        image_ref = image_ref + ":latest"

    if override_arch:
        target_arch = normalize_arch(override_arch)
        if target_arch is None:
            crit_error(f"unknown architecture '{override_arch}'.")
            sys.exit(1)
    else:
        target_arch = get_device_cpu_arch()

    # Pre-flight check: refuse early when no manifest is cached for this
    # image_ref + arch. This catches a typoed tag before we open a
    # network connection.
    manifest, _, _ = load_manifest_cache(image_ref, target_arch)
    if manifest is None:
        crit_error(
            f"No image found in local cache for "
            f"'{image_ref}' ({target_arch}). "
            f"Build it first with: {PROGRAM_NAME} build -t {image_ref}"
        )
        sys.exit(1)

    registry, _, _ = parse_image_ref(image_ref)
    display_registry = registry or "docker.io"

    if not quiet:
        log_info(f"Pushing '{image_ref}' ({target_arch}) "
                 f"to '{display_registry}'...")

    try:
        with BuildLock(image_ref, target_arch, command="push"):
            result = push_image(image_ref, target_arch)
    except KeyboardInterrupt:
        if sys.stderr.isatty():
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        log_error("Aborted by user.")
        sys.exit(1)
    except (urllib.error.URLError, OSError) as exc:
        if sys.stderr.isatty():
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        log_error(f"Network error: {exc}")
        sys.exit(1)
    except RuntimeError as exc:
        if sys.stderr.isatty():
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        log_error(f"Error: {exc}")
        sys.exit(1)

    if quiet:
        return

    log_info("Push complete.")
    msg()
    msg(f"{C['CYAN']}Repository: "
        f"{C['GREEN']}{result['registry']}/{result['repo']}{C['RST']}")
    msg(f"{C['CYAN']}Tag:        "
        f"{C['GREEN']}{result['tag']}{C['RST']}")
    if result.get("manifest_digest"):
        msg(f"{C['CYAN']}Digest:     "
            f"{C['GREEN']}{result['manifest_digest']}{C['RST']}")
    msg(f"{C['CYAN']}Uploaded:   "
        f"{C['GREEN']}{fmt_size(result['bytes_uploaded'])}{C['RST']}")
    msg()
