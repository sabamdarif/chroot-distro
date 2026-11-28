# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Extract a local archive into a rootfs: a plain tarball, an OCI image layout, or a
chroot-distro backup.

The format is decided by scanning through the tar terminator for `oci-layout`.
The scan retains only OCI paths and a 500-member sample. A plain tarball's leading components are
stripped by a vote (`detect_strip_count` scores each depth by how many entries put a
known rootfs directory first), because tarballs are published both with and without a
wrapper directory. OCI indexes can nest. Selection checks the Linux platform
claimed by the index and the image config before adopting a manifest.
Addressed documents are checked against their descriptors before parsing, and
layers before cache publication. Extraction uses the same open file it verified,
so a cache entry replaced by name cannot redirect the read.

A backup begins with `<name>/manifest.json` if metadata is present, followed by the
`<name>/rootfs` directory. A matching sidecar and rootfs tree also identify a backup
even if the explicit rootfs directory entry is absent. Extraction is limited to the
selected rootfs prefix, and only its sidecar is read as metadata. The probe, metadata
read and extraction use the same open archive.

Every member read out of the outer archive must be a regular file, since
`tarfile.extractfile` follows hardlinks and symlinks within the archive.

The rootfs is a descriptor throughout, for the reason `commands/install.py` explains.
A plain tarball returns None, since it carries no image metadata to record.
"""

import hashlib
import json
import os
import re
import sys
from collections.abc import Iterator
from typing import IO, Any, BinaryIO, NamedTuple

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.arch import Platform, platform_from_arch
from chroot_distro.atomic import atomic_write
from chroot_distro.constants import BASE_CACHE_DIR, IS_TERMUX, RUNTIME_DIR
from chroot_distro.helpers.docker import layer_cache_path
from chroot_distro.helpers.docker.media import (
    DOCKER_MANIFEST_LIST_MEDIA,
    DOCKER_MANIFEST_MEDIA,
    OCI_INDEX_MEDIA,
    OCI_MANIFEST_MEDIA,
)
from chroot_distro.helpers.download import MAX_METADATA_BYTES
from chroot_distro.helpers.tar_extract import extract_tar_stream, tar_path_parts
from chroot_distro.helpers.tar_stream import open_tar
from chroot_distro.message import escape_controls, log_info, quote_path, warn
from chroot_distro.names import is_valid_name
from chroot_distro.progress import ByteCounter, fmt_size

# Top-level directory names that signal a rootfs filesystem root.
_ROOTFS_DIRS = frozenset(
    {
        "bin",
        "dev",
        "etc",
        "home",
        "lib",
        "lib32",
        "lib64",
        "libx32",
        "media",
        "mnt",
        "opt",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
    }
)


_INDEX_MEDIA = (OCI_INDEX_MEDIA, DOCKER_MANIFEST_LIST_MEDIA)
_MANIFEST_MEDIA = (OCI_MANIFEST_MEDIA, DOCKER_MANIFEST_MEDIA)
_PLATFORM_FIELDS = ("os", "architecture", "variant")


def detect_strip_count(member_names: list) -> int:
    """Return how many leading path components to strip so the first
    remaining component lands at the rootfs root (e.g. `etc`, `usr`).
    """
    sample = member_names[:500]
    best_strip, best_score = 0, -1
    for strip in range(5):
        score = 0
        for name in sample:
            parts = name.lstrip("/").rstrip("/").split("/")
            if len(parts) > strip and parts[strip] in _ROOTFS_DIRS:
                score += 1
        if score > best_score:
            best_score, best_strip = score, strip
    return best_strip


class _Blob(NamedTuple):
    digest: str
    size: int

    @property
    def path(self) -> str:
        return "blobs/" + self.digest.replace(":", "/")


def _oci_blob(descriptor: object, label: str) -> _Blob:
    if not isinstance(descriptor, dict):
        raise RuntimeError(f"OCI {label} descriptor must be an object.")
    digest = descriptor.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise RuntimeError(f"OCI {label} descriptor must have a lowercase SHA-256 digest.")
    size = descriptor.get("size")
    if type(size) is not int or not 0 <= size < 2**63:
        raise RuntimeError(f"OCI {label} descriptor has an invalid size.")
    return _Blob(digest, size)


def _oci_open_member(
    tf: tarfile.TarFile, member_map: dict[str, tarfile.TarInfo], path: str, size: int | None = None
) -> IO[bytes]:
    member = member_map.get(path)
    if member is None:
        raise RuntimeError(f"OCI archive is missing required file: {path}")
    if not member.isreg():
        raise RuntimeError(f"OCI archive entry is not a regular file: {path}")
    if size is not None and member.size != size:
        raise RuntimeError(f"OCI archive entry size mismatch: {path}")
    fobj: IO[bytes] | None = tf.extractfile(member)
    if fobj is None:
        raise RuntimeError(f"OCI archive entry is not a regular file: {path}")
    return fobj


def _oci_read_json(tf, member_map, path: str, blob: _Blob | None = None) -> dict[str, Any]:
    """Verify addressed metadata on the wire before decoding its JSON."""
    if blob is not None and blob.size > MAX_METADATA_BYTES:
        raise RuntimeError(f"OCI metadata exceeds the size limit: {path}")
    with _oci_open_member(tf, member_map, path, None if blob is None else blob.size) as source:
        data = source.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        raise RuntimeError(f"OCI metadata exceeds the size limit: {path}")
    if blob is not None:
        if len(data) != blob.size:
            raise RuntimeError(f"OCI archive entry size mismatch: {path}")
        if "sha256:" + hashlib.sha256(data).hexdigest() != blob.digest:
            raise RuntimeError(f"OCI blob digest mismatch: {blob.digest}")
    try:
        document = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise RuntimeError(f"OCI archive entry is not valid JSON: {path}") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"OCI archive entry must be a JSON object: {path}")
    return document


def _oci_read_config(tf, member_map, manifest) -> dict[str, Any]:
    blob = _oci_blob(manifest.get("config"), "config")
    config = _oci_read_json(tf, member_map, blob.path, blob)
    if config.get("config") is not None and not isinstance(config["config"], dict):
        raise RuntimeError("OCI image config field 'config' must be an object or null.")
    return config


class _OciImage(NamedTuple):
    digest: str
    entries: tuple[dict[str, Any], ...]
    manifest: dict[str, Any]
    config: dict[str, Any]
    platform: Platform


def _oci_index_entries(index: dict[str, Any]) -> list[dict[str, Any]]:
    entries = index.get("manifests")
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise RuntimeError("OCI index must contain a list of manifest descriptors.")
    return entries


def _oci_platform_fields(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        key in value and not isinstance(value[key], str) for key in _PLATFORM_FIELDS
    ):
        raise RuntimeError(f"OCI {label} must have string OS, architecture and variant fields.")
    return {key: value[key] for key in _PLATFORM_FIELDS if key in value and (key != "variant" or value[key])}


def _merge_platform(
    inherited: dict[str, str], fields: dict[str, str], label: str
) -> dict[str, str]:
    for key in inherited.keys() & fields.keys():
        if inherited[key] != fields[key]:
            raise RuntimeError(f"OCI {label} disagrees with its index platform on {key}.")
    return inherited | fields


def _oci_platform(fields: dict[str, str]) -> Platform | None:
    architecture = fields.get("architecture", "")
    variant = fields.get("variant", "")
    if (architecture, variant) in (("arm64", "v8"), ("amd64", "v1")):
        variant = ""
    try:
        return Platform(fields.get("os", "linux"), architecture, variant)
    except ValueError:
        return None


def _oci_images(tf, member_map, index, wanted: Platform | None) -> Iterator[_OciImage]:
    stack: list[tuple[Iterator[dict[str, Any]], dict[str, str], tuple[dict[str, Any], ...]]] = [
        (iter(_oci_index_entries(index)), {}, ())
    ]
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    while stack:
        entries, inherited, ancestors = stack[-1]
        entry = next(entries, None)
        if entry is None:
            stack.pop()
            continue
        media_type = entry.get("mediaType")
        if (media_type is not None and media_type not in _INDEX_MEDIA + _MANIFEST_MEDIA) or entry.get("artifactType"):
            continue
        declared = _oci_platform_fields(entry.get("platform", {}), "index platform")
        fields = _merge_platform(inherited, declared, "nested descriptor")
        if fields.get("os", "linux") != "linux":
            continue
        if "architecture" in fields and _oci_platform(fields) is None:
            continue
        if wanted is not None and fields.get("architecture", wanted.architecture) != wanted.architecture:
            continue

        blob = _oci_blob(entry, "manifest")
        key = (blob.digest, tuple(sorted(fields.items())))
        if key in seen:
            continue
        seen.add(key)

        manifest = _oci_read_json(tf, member_map, blob.path, blob)
        descriptors = (*ancestors, entry)
        if media_type in _INDEX_MEDIA or (media_type is None and "manifests" in manifest):
            stack.append((iter(_oci_index_entries(manifest)), fields, descriptors))
            continue
        if manifest.get("artifactType"):
            continue
        config = _oci_read_config(tf, member_map, manifest)
        platform = _oci_platform(_merge_platform(fields, _oci_platform_fields(config, "image config"), "image config"))
        if platform is not None:
            yield _OciImage(blob.digest, descriptors, manifest, config, platform)


def _oci_select_image(tf, member_map, index, dist_arch: str, require_platform: bool) -> _OciImage:
    try:
        wanted = platform_from_arch(dist_arch)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    unspecified = None
    for image in _oci_images(tf, member_map, index, wanted):
        if image.platform == wanted:
            return image
        if image.platform.architecture == wanted.architecture and not image.platform.variant and unspecified is None:
            unspecified = image
    if unspecified is not None:
        return unspecified

    if not require_platform:
        foreign = None
        for image in _oci_images(tf, member_map, index, None):
            if foreign is not None and foreign.digest != image.digest:
                break
            foreign = image
        else:
            if foreign is not None:
                return foreign
    raise RuntimeError(f"No supported Linux image for '{wanted}' in the OCI index.")


def _oci_image_ref(entries: tuple[dict[str, Any], ...]) -> str:
    ref_keys = ("io.containerd.image.name", "org.opencontainers.image.ref.name")
    for entry in entries:
        annotations = entry.get("annotations", {})
        if not isinstance(annotations, dict) or any(
            key in annotations and not isinstance(annotations[key], str) for key in ref_keys
        ):
            raise RuntimeError("OCI manifest annotations must be an object with string image references.")
        for key in ref_keys:
            ref: str = annotations.get(key, "")
            if ref:
                return ref
    return ""


def _verify_layer(source: IO[bytes], blob: _Blob, output: IO[bytes] | None = None) -> None:
    hasher = hashlib.sha256()
    count = 0
    while chunk := source.read(min(1 << 18, blob.size - count + 1)):
        count += len(chunk)
        if count > blob.size:
            break
        hasher.update(chunk)
        if output is not None:
            output.write(chunk)
    if count != blob.size:
        raise RuntimeError(f"OCI layer size mismatch: {blob.digest}")
    if "sha256:" + hasher.hexdigest() != blob.digest:
        raise RuntimeError(f"OCI layer digest mismatch: {blob.digest}")


def _oci_cache_layer(tf, member_map, blob: _Blob, cache_path: str) -> None:
    """Publish only a layer whose streamed bytes match its descriptor."""
    with (
        _oci_open_member(tf, member_map, blob.path, blob.size) as source,
        atomic_write(cache_path, binary_mode=True) as out,
    ):
        _verify_layer(source, blob, out)


def _open_cached_layer(cache_path: str, blob: _Blob) -> BinaryIO:
    """Return a verified open layer at offset zero. The caller closes it."""
    cache_root = RUNTIME_DIR if IS_TERMUX else BASE_CACHE_DIR
    parent_parts = os.path.relpath(os.path.dirname(cache_path), cache_root).split(os.sep)
    root_fd = dirfd.opendir(cache_root)
    try:
        parent_fd = dirfd.descend_at(root_fd, parent_parts)
        try:
            fd, st = dirfd.open_regular_at(parent_fd, os.path.basename(cache_path), os.O_RDONLY)
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)
    source = os.fdopen(fd, "rb")
    try:
        if st.st_size != blob.size:
            raise RuntimeError(f"Cached OCI layer size mismatch: {blob.digest}")
        _verify_layer(source, blob)
        source.seek(0)
        return source
    except BaseException:
        source.close()
        raise


def _extract_oci(tf, member_map, rootfs_fd, dist_arch, require_platform) -> dict[str, object]:
    layout = _oci_read_json(tf, member_map, "oci-layout")
    if layout.get("imageLayoutVersion") != "1.0.0":
        raise RuntimeError("Unsupported OCI image layout version.")
    index = _oci_read_json(tf, member_map, "index.json")
    image = _oci_select_image(tf, member_map, index, dist_arch, require_platform)

    layers = image.manifest.get("layers")
    if not isinstance(layers, list):
        raise RuntimeError("OCI image manifest must contain a list of layers.")
    blobs = [_oci_blob(layer, "layer") for layer in layers]
    image_ref = _oci_image_ref(image.entries)

    n_layers = len(blobs)
    for i, blob in enumerate(blobs):
        short_id = blob.digest[:19]
        size_str = f" ({fmt_size(blob.size)})" if blob.size else ""
        cache_path = layer_cache_path(blob.digest)
        try:
            source = _open_cached_layer(cache_path, blob)
        except (OSError, RuntimeError):
            log_info(f"{short_id}: Caching layer {i + 1}/{n_layers}{size_str}...")
            _oci_cache_layer(tf, member_map, blob, cache_path)
            source = _open_cached_layer(cache_path, blob)
        with source:
            log_info(f"{short_id}: Applying layer {i + 1}/{n_layers}...")
            extract_tar_stream(source, blob.size, rootfs_fd, handle_whiteouts=True)

    return {
        "manifest": image.manifest,
        "image_config": image.config,
        "image_ref": image_ref,
        "arch": image.platform.to_arch(),
    }


def _detect_backup(members: list[tarfile.TarInfo]) -> tuple[str, bool] | None:
    """Return the backup wrapper and whether it has a manifest in the probe."""
    entries = [(tar_path_parts(member.name), member.isdir()) for member in members]
    sidecars = [
        parts[0]
        for parts, _ in entries
        if len(parts) == 2 and parts[0] not in ("", ".", "..") and parts[1] == "manifest.json"
    ]
    first, is_dir = next(((parts, is_dir) for parts, is_dir in entries if parts), ((), False))
    if is_dir and len(first) == 2 and first[1] == "rootfs" and is_valid_name(first[0]):
        return first[0], first[0] in sidecars

    roots = {
        parts[0] for parts, is_dir in entries if len(parts) >= 2 and parts[1] == "rootfs" and (is_dir or len(parts) > 2)
    }
    return next(((name, True) for name in sidecars if name in roots), None)


def _read_backup_manifest(tf: tarfile.TarFile, member: tarfile.TarInfo) -> dict | None:
    """Read a backup's matching manifest if it is a regular JSON file."""
    manifest_name = quote_path(member.name)
    if not member.isreg():
        warn(f"backup manifest '{manifest_name}' is not a regular file; ignoring it.")
        return None
    fobj = tf.extractfile(member)
    if fobj is None:
        return None
    with fobj:
        try:
            data = json.load(fobj)
        except (ValueError, RecursionError) as exc:
            warn(f"backup manifest '{manifest_name}' is not valid JSON ({escape_controls(str(exc))}); ignoring it.")
            return None
    return data if isinstance(data, dict) else None


def install_from_local_file(
    archive_path: str, rootfs_fd: int, dist_arch: str, *, require_platform: bool = False
) -> dict | None:
    """Detect an archive format and extract from the same open file throughout."""
    with open(archive_path, "rb") as archive:
        total_size = os.fstat(archive.fileno()).st_size
        probe: list[tarfile.TarInfo] = []
        member_map: dict[str, tarfile.TarInfo] = {}
        duplicates = False
        with open_tar(ByteCounter(archive), seekable=True) as tf:
            for member in tf:
                if len(probe) < 500:
                    probe.append(member)
                if member.name.startswith("/"):
                    continue
                path = "/".join(tar_path_parts(member.name))
                if path in ("oci-layout", "index.json") or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", path):
                    duplicates |= path in member_map
                    member_map[path] = member

            if "oci-layout" in member_map:
                if duplicates:
                    raise RuntimeError("OCI archive contains duplicate layout entries.")
                return _extract_oci(tf, member_map, rootfs_fd, dist_arch, require_platform)

            backup = _detect_backup(probe)
            metadata = None
            if backup is not None:
                wrapper, has_manifest = backup
                if has_manifest:
                    manifest = next(member for member in probe if tar_path_parts(member.name) == (wrapper, "manifest.json"))
                    metadata = _read_backup_manifest(tf, manifest)

        archive.seek(0)
        if backup is None:
            strip = detect_strip_count([member.name for member in probe])
            extract_tar_stream(archive, total_size, rootfs_fd, strip=strip)
        else:
            extract_tar_stream(archive, total_size, rootfs_fd, rootfs_prefix=(backup[0], "rootfs"))
        return metadata
