# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Extract a local archive into a rootfs: a plain tarball, an OCI image layout, or a
chroot-distro backup.

The format is decided by streaming the first 500 members and looking for `oci-layout`,
so a plain tarball is never indexed in full. A plain tarball's leading components are
stripped by a vote (`detect_strip_count` scores each depth by how many entries put a
known rootfs directory first), because tarballs are published both with and without a
wrapper directory. An OCI archive is walked from index to manifest to config.
Addressed documents are checked against their descriptors before parsing, and
layers before cache publication. Extraction uses the same open file it verified,
so a cache entry replaced by name cannot redirect the read.

A chroot-distro backup is a plain tar whose members are `<name>/manifest.json` (always
the first entry) and `<name>/rootfs/...`. It is recognised by that shape and its
`manifest.json` is read back and returned as metadata, so `install` can write it out
and `run` works; the rootfs is unpacked by the plain-tarball path with a fixed strip of
2 (dropping `<name>/rootfs`, and the shorter manifest member falls outside that tree),
since the voted strip ties toward 0 for a container name that is itself a rootfs dir.

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
from typing import IO, Any, BinaryIO, NamedTuple

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

from chroot_distro import dirfd
from chroot_distro.atomic import atomic_write
from chroot_distro.constants import BASE_CACHE_DIR, IS_TERMUX, RUNTIME_DIR
from chroot_distro.helpers.docker import (
    ARCH_TO_DOCKER,
    layer_cache_path,
)
from chroot_distro.helpers.tar_extract import extract_tar_stream, extract_tar_to_rootfs
from chroot_distro.message import log_info, warn
from chroot_distro.progress import clear_bar, fmt_size, progress_active

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


# Reverse of ARCH_TO_DOCKER: Docker architecture name → chroot-distro arch.
_DOCKER_TO_ARCH = {docker: pd for pd, (docker, _) in ARCH_TO_DOCKER.items()}


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


def extract_plain_tar(archive_path: str, strip: int, rootfs_fd: int) -> None:
    """Stream-extract a plain rootfs tarball into the *rootfs_fd* tree."""
    extract_tar_to_rootfs(archive_path, rootfs_fd, strip=strip)


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
    with _oci_open_member(tf, member_map, path, None if blob is None else blob.size) as source:
        data = source.read()
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
    if "architecture" in config and not isinstance(config["architecture"], str):
        raise RuntimeError("OCI image config architecture must be a string.")
    if config.get("config") is not None and not isinstance(config["config"], dict):
        raise RuntimeError("OCI image config field 'config' must be an object or null.")
    return config


def _oci_find_manifest_entry(tf, member_map, index_manifests, dist_arch):
    if len(index_manifests) == 1:
        return index_manifests[0]

    docker_arch = ARCH_TO_DOCKER.get(dist_arch, (dist_arch, ""))[0]

    platform_entries = [e for e in index_manifests if "platform" in e]
    if platform_entries:
        for entry in platform_entries:
            p = entry["platform"]
            if not isinstance(p, dict) or any(
                key in p and not isinstance(p[key], str) for key in ("architecture", "os")
            ):
                raise RuntimeError("OCI index platform must be an object with string architecture and OS.")
            if p.get("architecture") == docker_arch and p.get("os") == "linux":
                return entry
        raise RuntimeError(f"No manifest found for architecture '{dist_arch}' in OCI index (tried {docker_arch}).")

    for entry in index_manifests:
        blob = _oci_blob(entry, "manifest")
        manifest = _oci_read_json(tf, member_map, blob.path, blob)
        config = _oci_read_config(tf, member_map, manifest)
        if config.get("architecture") == docker_arch:
            return entry

    raise RuntimeError(f"No manifest found for architecture '{dist_arch}' in OCI image (tried {docker_arch}).")


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


def _extract_oci(tf, member_map, rootfs_fd, dist_arch) -> dict[str, object]:
    index = _oci_read_json(tf, member_map, "index.json")
    index_manifests = index.get("manifests")
    if not isinstance(index_manifests, list) or not index_manifests or not all(
        isinstance(entry, dict) for entry in index_manifests
    ):
        raise RuntimeError("OCI index.json must contain a nonempty list of manifest descriptors.")

    manifest_entry = _oci_find_manifest_entry(tf, member_map, index_manifests, dist_arch)

    manifest_blob = _oci_blob(manifest_entry, "manifest")
    manifest = _oci_read_json(tf, member_map, manifest_blob.path, manifest_blob)
    image_config = _oci_read_config(tf, member_map, manifest)

    docker_arch = image_config.get("architecture", "")
    actual_arch = _DOCKER_TO_ARCH.get(docker_arch, dist_arch)

    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise RuntimeError("OCI image manifest must contain a nonempty list of layers.")
    blobs = [_oci_blob(layer, "layer") for layer in layers]

    annotations = manifest_entry.get("annotations", {})
    ref_keys = ("io.containerd.image.name", "org.opencontainers.image.ref.name")
    if not isinstance(annotations, dict) or any(
        key in annotations and not isinstance(annotations[key], str) for key in ref_keys
    ):
        raise RuntimeError("OCI manifest annotations must be an object with string image references.")
    image_ref = next((annotations[key] for key in ref_keys if annotations.get(key)), "")

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
        "manifest": manifest,
        "image_config": image_config,
        "image_ref": image_ref,
        "arch": actual_arch,
    }


def _detect_backup_manifest(member_names: list) -> str | None:
    """Return the `<name>/manifest.json` member name if these look like a backup.

    A chroot-distro backup nests everything under one top-level directory holding
    `manifest.json` and a `rootfs/` tree. The manifest is always the first member,
    so it is within the probe window even for a large rootfs.
    """
    manifest_name: str | None = None
    top = ""
    for name in member_names:
        parts = str(name).lstrip("/").split("/")
        if len(parts) == 2 and parts[1] == "manifest.json":
            manifest_name, top = str(name), parts[0]
            break
    if manifest_name is None:
        return None
    rootfs_prefix = f"{top}/rootfs"
    for name in member_names:
        clean = str(name).lstrip("/").rstrip("/")
        if clean == rootfs_prefix or clean.startswith(rootfs_prefix + "/"):
            return manifest_name
    return None


def _read_backup_manifest(archive_path: str, manifest_name: str) -> dict | None:
    """Read and parse a backup's `manifest.json` member, or None if unusable."""
    with tarfile.open(archive_path, "r|*") as tf:
        for m in tf:
            if m.name.lstrip("/") != manifest_name.lstrip("/"):
                continue
            if not m.isreg():
                # extractfile() follows hardlinks/symlinks within the archive; a
                # non-regular manifest member could redirect this read elsewhere.
                warn(f"backup manifest '{manifest_name}' is not a regular file; ignoring it.")
                return None
            fobj = tf.extractfile(m)
            if fobj is None:
                return None
            try:
                data = json.loads(fobj.read())
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                warn(f"backup manifest '{manifest_name}' is not valid JSON ({exc}); ignoring it.")
                return None
            finally:
                fobj.close()
            return data if isinstance(data, dict) else None
    return None


def install_from_local_file(archive_path: str, rootfs_fd: int, dist_arch: str) -> dict | None:
    """Open *archive_path*, detect its format, and extract into *rootfs_fd*.

    The rootfs is a **descriptor**: `install` walks containers/<name>/rootfs
    down with O_NOFOLLOW and hands the result straight through, so nothing
    between that check and the last member written resolves the name again.
    """
    probe_names: list = []
    is_oci = False
    with tarfile.open(archive_path, "r|*") as tf_probe:
        for m in tf_probe:
            probe_names.append(m.name)
            if m.name == "oci-layout":
                is_oci = True
                break
            if len(probe_names) >= 500:
                break

    if is_oci:
        with tarfile.open(archive_path, "r:*") as tf:
            if progress_active():
                log_info("Indexing OCI archive...")
                sys.stderr.flush()
            raw_members = tf.getmembers()
            clear_bar()
            member_map = {m.name: m for m in raw_members}
            return _extract_oci(tf, member_map, rootfs_fd, dist_arch)

    backup_manifest = _detect_backup_manifest(probe_names)
    metadata = _read_backup_manifest(archive_path, backup_manifest) if backup_manifest else None

    # A detected backup's layout is fixed (<name>/rootfs/...), so strip is 2 here
    # rather than voted: detect_strip_count ties toward 0 for a name like "usr".
    strip = 2 if backup_manifest else detect_strip_count(probe_names)
    extract_plain_tar(archive_path, strip, rootfs_fd)
    return metadata
