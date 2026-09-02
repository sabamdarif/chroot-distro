# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Host NVIDIA driver integration: what to bind, and what to set, for a GPU guest.

Ported from the NVIDIA integration in distrobox's `distrobox-init`
(https://github.com/89luca89/distrobox), created by Luca Di Maio and licensed
GPL-3.0, then rewritten for chroot-distro's bind lists and path mapping.

A proprietary NVIDIA userspace has to match the kernel module exactly, so the
guest cannot ship its own: the host's libraries, ICD descriptors and CLI tools
are bound in, and `_host_lib_to_guest_path` remaps each one onto the library
directory `_detect_guest_lib_dirs` found in the image (multiarch, lib64, or plain
lib) for the file's own ELF class. The class comes from the file because no host
layout puts it in the directory name the same way: Debian keeps both in
`/usr/lib/<triplet>`, Fedora keeps 64-bit in `/usr/lib64` and 32-bit in
`/usr/lib`, Arch keeps 64-bit in `/usr/lib` and 32-bit in `/usr/lib32`. WSL2 is
the second supported shape, where the libraries live under `/usr/lib/wsl` and
that whole directory is bound instead.

Three exclusions are the load-bearing part, and each one is a guest that broke:

* the vendor-neutral GLVND and GBM dispatch names (`_GLVND_NEUTRAL_BASENAMES`)
  belong to the container's own stack and are never bound, since the host copies
  are usually symlinks into vendor-specific targets and shadowing the guest's
  real file corrupts its loader;
* a zero-byte source is skipped, because binding one leaves a stub `ldconfig`
  rejects, and a symlink is resolved so what lands in the guest is the file and
  not a dangling name;
* configuration is bound from an explicit list of known ICD and Xorg paths, never
  from a walk of `/etc` matching the name "nvidia", which would carry unrelated
  host files into the container.

A guest path that already holds something is left alone, since a parent bind or
the image's own package may provide it, but a zero-byte one is this program's own
leftover: `mount_manager` creates an empty file as a bind target and the unmount
leaves it, so treating that as the image's library would starve every session
after the first. `run_ldconfig_in_chroot` runs the *guest's* own `ldconfig`
through `chroot_and_run` to refresh its cache after the binds, and stays
non-fatal: an image without one simply keeps whatever cache it had.
"""

from __future__ import annotations

import fnmatch
import glob
import logging
import os
import re
from collections.abc import Iterator

from chroot_distro.syscalls.chroot import chroot_and_run

log = logging.getLogger(__name__)


def is_wsl() -> bool:
    """Return True when running inside WSL2."""
    try:
        with open("/proc/version") as f:
            version_str = f.read().lower()
        return "microsoft" in version_str or "wsl" in version_str
    except OSError:
        return False


def detect_nvidia_gpu() -> bool:
    """Return True when the host exposes an NVIDIA GPU.

    Checks (in order, short-circuits on first hit):
    1. ``/dev/nvidia0`` exists (native Linux proprietary driver)
    2. ``/dev/dxg`` exists **and** NVIDIA libraries in ``/usr/lib/wsl/lib/`` (WSL2)
    3. Any ``libcuda*.so*`` or ``libnvidia*.so*`` found under ``/usr/lib*/``
    """
    if os.path.exists("/dev/nvidia0"):
        log.debug("NVIDIA detected: /dev/nvidia0 exists")
        return True

    if os.path.exists("/dev/dxg"):
        wsl_lib = "/usr/lib/wsl/lib"
        if os.path.isdir(wsl_lib) and any(f.startswith(("libcuda", "libnvidia")) for f in os.listdir(wsl_lib)):
            log.debug("NVIDIA detected: /dev/dxg + WSL libs present")
            return True

    for lib_dir in ("/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"):
        if not os.path.isdir(lib_dir):
            continue
        try:
            entries = os.listdir(lib_dir)
        except OSError:
            continue
        for entry in entries:
            lower = entry.lower()
            if ("libcuda" in lower or "libnvidia" in lower) and ".so" in lower:
                log.debug("NVIDIA detected: found %s in %s", entry, lib_dir)
                return True

    return False


_NATIVE_NVIDIA_DEVICES = (
    "/dev/nvidia0",
    "/dev/nvidia1",
    "/dev/nvidia2",
    "/dev/nvidia3",
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
)

_DRI_DEVICE_PATTERNS = (
    "/dev/dri/card*",
    "/dev/dri/renderD*",
)


def find_nvidia_device_nodes() -> list[tuple[str, str]]:
    """Return ``(host_path, guest_path)`` pairs for GPU device nodes.

    Includes:
    - ``/dev/nvidia*`` (native Linux)
    - ``/dev/dxg`` (WSL2)
    - ``/dev/dri/*`` (DRM render nodes for Mesa)
    """
    binds: list[tuple[str, str]] = []

    for dev in _NATIVE_NVIDIA_DEVICES:
        if os.path.exists(dev):
            binds.append((dev, dev))

    if os.path.exists("/dev/dxg"):
        binds.append(("/dev/dxg", "/dev/dxg"))

    for pattern in _DRI_DEVICE_PATTERNS:
        for dev in sorted(glob.glob(pattern)):
            if os.path.exists(dev):
                binds.append((dev, dev))

    return binds


_NVIDIA_LIB_PATTERNS = (
    "*lib*nvidia*.so*",
    "*nvidia*.so*",
    "libcuda*.so*",
    "libnvcuvid*",
    "libnvoptix*",
)

# The patterns as one alternation, so a basename is tested against all of them in
# a single match: a merged-usr host keeps six figures of files under /usr/lib and
# a separate pass per pattern over that tree costs seconds.
_NVIDIA_LIB_RE = re.compile("|".join(fnmatch.translate(pattern) for pattern in _NVIDIA_LIB_PATTERNS))

# Vendor-neutral GLVND dispatch libraries. These are provided by the
# container's own Mesa/GLVND stack and must NEVER be bound from the host:
# the host copies are frequently symlinks resolving to vendor-specific
# targets, and shadowing the guest's real files (or leaving an empty stub)
# corrupts its loader ("libGL.so is empty, not checked").
_GLVND_NEUTRAL_BASENAMES = (
    "libGL.so",
    "libEGL.so",
    "libGLX.so",
    "libGLESv1_CM.so",
    "libGLESv2.so",
    "libOpenGL.so",
    "libGLdispatch.so",
    "libgbm.so",
)


def _is_glvnd_neutral(path: str) -> bool:
    """Return True for vendor-neutral GLVND/GBM dispatch library names."""
    base = os.path.basename(path)
    return any(base == name or base.startswith(name + ".") for name in _GLVND_NEUTRAL_BASENAMES)


def _detect_guest_lib_dirs(rootfs: str) -> tuple[str, str | None]:
    """Determine the guest's 64-bit and 32-bit library directories.

    Returns ``(lib64_dir, lib32_dir)`` as absolute guest paths
    (e.g. ``"/usr/lib/x86_64-linux-gnu/"``). *lib32_dir* is None when the image
    has no 32-bit directory of its own: a host 32-bit library would otherwise
    either land in a multiarch tree the guest never had or collide with its
    64-bit namesake in a merged /usr/lib.
    """
    # Multi-arch layout (Debian/Ubuntu)
    if os.path.isdir(os.path.join(rootfs, "usr/lib/x86_64-linux-gnu")):
        lib64 = "/usr/lib/x86_64-linux-gnu/"
        lib32 = "/usr/lib/i386-linux-gnu/"
    # Red Hat / Arch layout
    elif os.path.isdir(os.path.join(rootfs, "usr/lib64")):
        lib64 = "/usr/lib64/"
        lib32 = "/usr/lib/"
    else:
        lib64 = "/usr/lib/"
        lib32 = "/usr/lib/"

    if os.path.isdir(os.path.join(rootfs, "usr/lib32")):
        lib32 = "/usr/lib32/"

    if lib32 == lib64 or not os.path.isdir(os.path.join(rootfs, lib32.strip("/"))):
        return lib64, None

    return lib64, lib32


def _is_elf64(path: str) -> bool:
    """Return True when *path* is a 64-bit object (ELF ``EI_CLASS`` is ELFCLASS64).

    Anything that is not a readable ELF file counts as 64-bit: the guest's
    primary library directory is where an unrecognised file does the least harm.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(5)
    except OSError:
        return True
    if len(header) < 5 or header[:4] != b"\x7fELF":
        return True
    return header[4] == 2


# Host library directories, most specific first so /usr/lib/ stays the catch-all.
_HOST_LIB_DIRS = (
    "/usr/lib/x86_64-linux-gnu/",
    "/usr/lib/i386-linux-gnu/",
    "/usr/lib64/",
    "/usr/lib32/",
    "/usr/lib/",
)

# Where the search starts. A multiarch directory gets no entry of its own because
# it sits under /usr/lib and the walk reaches it; only a sibling tree needs one.
_HOST_LIB_ROOTS = (
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
)


def _host_lib_to_guest_path(host_path: str, lib64: str, lib32: str | None) -> str | None:
    """Map a host library path to the equivalent guest library path.

    The destination directory follows the file's ELF class, not the name of the
    host directory holding it, and everything below that directory is kept so a
    ``vdpau/`` or ``nvidia/xorg/`` subdirectory survives the move. None means the
    guest has nowhere to put it; a path under no known library directory is
    returned unchanged.
    """
    guest_dir = lib64 if _is_elf64(host_path) else lib32
    if guest_dir is None:
        return None
    for host_dir in _HOST_LIB_DIRS:
        if host_path.startswith(host_dir):
            return guest_dir + host_path[len(host_dir) :]
    return host_path


def _guest_ships_library(guest_abs: str) -> bool:
    """Return True when the guest already holds a real library at *guest_abs*.

    A zero-byte file is not one: `mount_manager` creates an empty file as the
    target of a single-file bind and the unmount leaves it behind, so the stub
    (or a soname symlink the guest's ldconfig pointed at one) has to be bound
    over rather than mistaken for the image's own library.
    """
    try:
        return os.stat(guest_abs).st_size > 0
    except OSError:
        return False


def _walk_host_libraries() -> Iterator[str]:
    """Yield every path under `_HOST_LIB_ROOTS` whose basename names an NVIDIA library.

    A root that is another name for one already walked is skipped, since /usr/lib64
    is a symlink to /usr/lib on an Arch-family host. Symlinked subdirectories are
    followed, because a distro may keep the libraries behind one.
    """
    walked: set[str] = set()
    for root in _HOST_LIB_ROOTS:
        if not os.path.isdir(root):
            continue
        real_root = os.path.realpath(root)
        if real_root in walked:
            continue
        walked.add(real_root)
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=True):
            for name in filenames:
                if _NVIDIA_LIB_RE.match(name):
                    yield os.path.join(dirpath, name)


def find_nvidia_libraries(rootfs: str) -> list[tuple[str, str]]:
    """Find NVIDIA ``.so`` files on the host and map them to guest paths.

    Returns ``(host_path, guest_path)`` pairs for bind-mounting.
    """
    lib64, lib32 = _detect_guest_lib_dirs(rootfs)
    binds: list[tuple[str, str]] = []
    seen_guests: set[str] = set()

    for lib_path in _walk_host_libraries():
        if not os.path.isfile(lib_path):
            continue

        # The container's own GLVND stack owns these; see
        # _GLVND_NEUTRAL_BASENAMES.
        if _is_glvnd_neutral(lib_path):
            continue

        real_path = lib_path
        if os.path.islink(lib_path):
            real_path = os.path.realpath(lib_path)
            if not os.path.isfile(real_path):
                continue

        # Skip zero-byte sources: a real library is never empty, and
        # binding one leaves an empty stub that ldconfig rejects.
        try:
            if os.path.getsize(real_path) == 0:
                continue
        except OSError:
            continue

        guest_path = _host_lib_to_guest_path(lib_path, lib64, lib32)
        if guest_path is None:
            continue

        if guest_path in seen_guests:
            continue
        seen_guests.add(guest_path)

        # A parent bind mount or the image's own package may provide it.
        if _guest_ships_library(os.path.join(rootfs, guest_path.lstrip("/"))):
            continue

        binds.append((real_path, guest_path))

    return binds


def find_wsl_libraries(rootfs: str) -> list[tuple[str, str]]:
    """Find WSL-specific NVIDIA/D3D12 libraries to bind-mount.

    On WSL2, the critical GPU libraries live under ``/usr/lib/wsl/lib/``
    and driver directories under ``/usr/lib/wsl/drivers/``. We bind the
    entire ``/usr/lib/wsl`` directory so both are accessible.
    """
    wsl_root = "/usr/lib/wsl"
    if not os.path.isdir(wsl_root):
        return []

    return [(wsl_root, wsl_root)]


def find_nvidia_configs() -> list[tuple[str, str]]:
    """Find NVIDIA configuration and ICD descriptor files on the host.

    Returns ``(host_path, guest_path)`` pairs; guest paths equal host paths.
    """
    binds: list[tuple[str, str]] = []

    # Only these known ICD/EGL/Vulkan config paths are bound, never a full
    # /etc walk matching on the name "nvidia", which would leak unrelated host
    # files (logs, backups, credentials) into the container.
    config_globs = (
        "/usr/share/glvnd/egl_vendor.d/10_nvidia.json",
        "/usr/share/egl/egl_external_platform.d/10_nvidia_wayland.json",
        "/usr/share/egl/egl_external_platform.d/15_nvidia_gbm.json",
        "/usr/share/vulkan/icd.d/nvidia_icd*.json",
        "/usr/share/vulkan/icd.d/nvidia_layers.json",
        "/usr/share/vulkan/implicit_layer.d/nvidia_layers.json",
        "/etc/OpenCL/vendors/nvidia.icd",
        "/usr/share/nvidia/nvoptix.bin",
        "/usr/share/X11/xorg.conf.d/10-nvidia.conf",
        "/usr/share/X11/xorg.conf.d/nvidia-drm-outputclass.conf",
    )
    for pattern in config_globs:
        for path in glob.glob(pattern):
            if os.path.isfile(path) and (path, path) not in binds:
                binds.append((path, path))

    return binds


def find_nvidia_binaries() -> list[tuple[str, str]]:
    """Find NVIDIA CLI tools (nvidia-smi, etc.) on the host.

    Returns ``(host_path, guest_path)`` pairs. A search directory that is only
    another name for one already walked (`/bin` -> `/usr/bin` on a merged-usr
    host) is skipped, so one tool does not arrive under four guest paths.
    """
    binds: list[tuple[str, str]] = []
    search_dirs = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
    seen_dirs: set[str] = set()

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        real_dir = os.path.realpath(d)
        if real_dir in seen_dirs:
            continue
        seen_dirs.add(real_dir)
        try:
            for entry in os.listdir(d):
                if "nvidia" in entry.lower():
                    full = os.path.join(d, entry)
                    if os.path.isfile(full):
                        real = os.path.realpath(full) if os.path.islink(full) else full
                        binds.append((real, full))
        except OSError:
            continue

    # WSL nvidia-smi is inside /usr/lib/wsl/lib/
    wsl_smi = "/usr/lib/wsl/lib/nvidia-smi"
    if os.path.isfile(wsl_smi):
        binds.append((wsl_smi, "/usr/bin/nvidia-smi"))

    return binds


def nvidia_env_vars() -> dict[str, str]:
    """Return environment variables to enable GPU rendering.

    On WSL2: sets ``GALLIUM_DRIVER=d3d12`` for Mesa's D3D12 backend.
    On native: sets PRIME offload variables for the NVIDIA proprietary driver.
    """
    env: dict[str, str] = {}

    if is_wsl():
        env["GALLIUM_DRIVER"] = "d3d12"
        env["MESA_D3D12_DEFAULT_DEVICE_TYPE"] = "GPU"
        env["LIBGL_ALWAYS_SOFTWARE"] = "0"
    else:
        env["__NV_PRIME_RENDER_OFFLOAD"] = "1"
        env["__GLX_VENDOR_LIBRARY_NAME"] = "nvidia"

    return env


def setup_ldconfig_for_wsl(rootfs: str) -> None:
    """Ensure ``/usr/lib/wsl/lib`` is in the guest's ldconfig search path.

    Creates ``/etc/ld.so.conf.d/wsl-nvidia.conf`` inside the rootfs
    if it doesn't already exist, so that ``ldconfig`` picks up the
    WSL GPU libraries.
    """
    conf_dir = os.path.join(rootfs, "etc", "ld.so.conf.d")
    conf_file = os.path.join(conf_dir, "wsl-nvidia.conf")

    if os.path.exists(conf_file):
        return

    try:
        os.makedirs(conf_dir, exist_ok=True)
        with open(conf_file, "w") as f:
            f.write("/usr/lib/wsl/lib\n")
        log.debug("Created %s for WSL NVIDIA ldconfig", conf_file)
    except OSError as e:
        log.debug("Failed to create WSL ldconfig config: %s", e)


def run_ldconfig_in_chroot(rootfs: str) -> None:
    """Run ``ldconfig`` inside the chroot to refresh the shared library cache.

    Non-fatal: logs on failure but does not raise.
    """
    for guest_path in ("/sbin/ldconfig", "/usr/sbin/ldconfig"):
        if os.path.isfile(os.path.join(rootfs, guest_path.lstrip("/"))):
            break
    else:
        log.debug("ldconfig not found in chroot, skipping cache refresh")
        return

    try:
        result = chroot_and_run(
            rootfs,
            [guest_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError as e:
        log.debug("ldconfig execution error: %s", e)
        return

    if result.returncode == 0:
        log.debug("ldconfig refreshed successfully in chroot")
    else:
        log.debug("ldconfig failed: %s", str(result.stderr).strip())


def get_nvidia_integration(
    rootfs: str,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Return everything needed to integrate host NVIDIA drivers into the chroot.

    Returns:
        ``(bind_mounts, env_vars)`` where *bind_mounts* is a list of
        ``(host_path, guest_path)`` pairs and *env_vars* is a dict of
        environment variables to inject.

    Call this only after ``detect_nvidia_gpu()`` returns True.
    """
    binds: list[tuple[str, str]] = []
    env = nvidia_env_vars()

    binds.extend(find_nvidia_device_nodes())

    if is_wsl():
        wsl_binds = find_wsl_libraries(rootfs)
        binds.extend(wsl_binds)
        setup_ldconfig_for_wsl(rootfs)
    else:
        binds.extend(find_nvidia_libraries(rootfs))

    binds.extend(find_nvidia_configs())

    binds.extend(find_nvidia_binaries())

    seen: set[tuple[str, str]] = set()
    unique_binds: list[tuple[str, str]] = []
    for pair in binds:
        if pair not in seen:
            seen.add(pair)
            unique_binds.append(pair)

    log.debug(
        "NVIDIA integration: %d bind mounts, %d env vars",
        len(unique_binds),
        len(env),
    )

    return unique_binds, env
