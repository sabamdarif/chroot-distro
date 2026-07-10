import json
import os
import sys

from chroot_distro.helpers.docker import layer_cache_path
from chroot_distro.helpers.layer_diff import (
    baseline_cache_is_valid,
    cached_baseline_from_layers,
    diff_against_baseline,
    snapshot,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import C, crit_error, msg
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_manifest, container_rootfs
from chroot_distro.progress import loading_line

# Top-level directories that are bind/pseudo mounts at login time and never
# part of the image's own filesystem; excluding them keeps `diff` focused on
# real user changes (matches the spirit of `docker diff`).
_EXCLUDED_TOP = frozenset({"dev", "proc", "sys", "run", "tmp"})


def _is_excluded(rel: str) -> bool:
    top = rel.split("/", 1)[0]
    return top in _EXCLUDED_TOP


def _load_layer_digests(manifest_path: str) -> list[str]:
    with open(manifest_path, encoding="utf-8") as fh:
        data = json.load(fh)
    manifest = data.get("manifest") or {}
    layers = manifest.get("layers") or []
    return [layer.get("digest", "") for layer in layers if layer.get("digest")]


def command_diff(args) -> None:
    """Show files/directories changed in a container relative to its image."""
    container_name = args.container_name
    require_valid_name(container_name)

    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    manifest_path = container_manifest(container_name)
    if not os.path.isfile(manifest_path):
        crit_error(
            f"container '{container_name}' has no image manifest; "
            f"diff is only available for containers installed from an OCI/Docker image."
        )
        sys.exit(1)

    with ContainerLock(container_name, exclusive=False, command="diff"):
        try:
            digests = _load_layer_digests(manifest_path)
        except (OSError, ValueError) as exc:
            crit_error(f"failed to read manifest for '{container_name}': {exc}")
            sys.exit(1)

        if not digests:
            crit_error(f"container '{container_name}' manifest lists no image layers.")
            sys.exit(1)

        baseline_cache = os.path.join(container_dir(container_name), "diff_baseline.json")

        # The cached baseline (kept under the container dir, which survives
        # 'clear-cache') lets us reconstruct the image without the raw layer
        # tars. Only require the layer blobs when no valid baseline exists —
        # otherwise 'clear-cache' would needlessly break 'diff'.
        layer_paths = [layer_cache_path(d) for d in digests]
        if not baseline_cache_is_valid(baseline_cache, digests):
            missing = [d for d, p in zip(digests, layer_paths, strict=False) if not os.path.isfile(p)]
            if missing:
                crit_error(
                    f"cannot diff '{container_name}': {len(missing)} image layer(s) are no longer "
                    f"in the cache and no baseline has been recorded yet. "
                    f"Run 'chroot-distro diff' before 'clear-cache', or reinstall to rebuild the cache."
                )
                sys.exit(1)
        with loading_line("Reconstructing image baseline..."):
            baseline = cached_baseline_from_layers(layer_paths, digests, baseline_cache)
        with loading_line("Scanning container filesystem..."):
            live = snapshot(rootfs)

    added, modified, deleted = diff_against_baseline(baseline, live)

    rows: list[tuple[str, str, str]] = []
    for path in modified:
        if not _is_excluded(path):
            rows.append(("C", C["YELLOW"], path))
    for path in added:
        if not _is_excluded(path):
            rows.append(("A", C["GREEN"], path))
    for path in deleted:
        if not _is_excluded(path):
            rows.append(("D", C["RED"], path))

    if not rows:
        msg()
        msg(f"{C['CYAN']}No changes in container '{container_name}'.{C['RST']}")
        msg()
        return

    rows.sort(key=lambda r: r[2])
    for marker, color, path in rows:
        msg(f"{color}{marker} /{path}{C['RST']}")


__all__ = ("command_diff",)
