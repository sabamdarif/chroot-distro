"""NVIDIA GPU auto-detection and host-driver integration for chroot sessions.

This module mirrors the NVIDIA integration logic from distrobox-init
(lines 2000-2181) but adapted for chroot-distro's Python-based architecture.

It automatically detects whether the host has an NVIDIA GPU (both native
Linux and WSL2), locates driver libraries / config files / binaries /
device nodes, and returns bind-mount lists + environment variables that
the login command can apply to make the GPU work inside the chroot.
"""

from __future__ import annotations

import glob
import logging
import os
import subprocess

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


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
    # 1. Native NVIDIA device nodes
    if os.path.exists("/dev/nvidia0"):
        log.debug("NVIDIA detected: /dev/nvidia0 exists")
        return True

    # 2. WSL2 with NVIDIA
    if os.path.exists("/dev/dxg"):
        wsl_lib = "/usr/lib/wsl/lib"
        if os.path.isdir(wsl_lib) and any(f.startswith(("libcuda", "libnvidia")) for f in os.listdir(wsl_lib)):
            log.debug("NVIDIA detected: /dev/dxg + WSL libs present")
            return True

    # 3. Libraries on native host
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


# ---------------------------------------------------------------------------
# Device nodes
# ---------------------------------------------------------------------------

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

    # Native NVIDIA device nodes
    for dev in _NATIVE_NVIDIA_DEVICES:
        if os.path.exists(dev):
            binds.append((dev, dev))

    # WSL2 DXG device
    if os.path.exists("/dev/dxg"):
        binds.append(("/dev/dxg", "/dev/dxg"))

    # DRI render / card nodes (used by Mesa for GPU access)
    for pattern in _DRI_DEVICE_PATTERNS:
        for dev in sorted(glob.glob(pattern)):
            if os.path.exists(dev):
                binds.append((dev, dev))

    return binds


# ---------------------------------------------------------------------------
# Library discovery
# ---------------------------------------------------------------------------

# Patterns for NVIDIA shared-object files (case-insensitive matching)
_NVIDIA_LIB_PATTERNS = (
    "*lib*nvidia*.so*",
    "*nvidia*.so*",
    "libcuda*.so*",
    "libnvcuvid*",
    "libnvoptix*",
)

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


def _detect_guest_lib_dirs(rootfs: str) -> tuple[str, str]:
    """Determine the guest's 64-bit and 32-bit library directories.

    Returns ``(lib64_dir, lib32_dir)`` as absolute guest paths
    (e.g. ``"/usr/lib/x86_64-linux-gnu/"``).
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

    return lib64, lib32


def _host_lib_to_guest_path(host_path: str, lib64: str, lib32: str) -> str:
    """Map a host library path to the equivalent guest library path.

    Follows the same remapping logic as distrobox-init lines 2137-2142.
    """
    path = host_path
    # Multi-arch → guest lib64
    path = path.replace("/usr/lib/x86_64-linux-gnu/", lib64)
    path = path.replace("/usr/lib/i386-linux-gnu/", lib32)
    # RPM/Arch → guest lib64
    path = path.replace("/usr/lib64/", lib64)
    path = path.replace("/usr/lib32/", lib32)
    # Catch-all: /usr/lib/ → lib32 (32-bit libs on multilib systems)
    # Only apply if none of the above matched
    if path == host_path:
        path = path.replace("/usr/lib/", lib32)
    return path


def find_nvidia_libraries(rootfs: str) -> list[tuple[str, str]]:
    """Find NVIDIA ``.so`` files on the host and map them to guest paths.

    Returns ``(host_path, guest_path)`` pairs for bind-mounting.
    """
    lib64, lib32 = _detect_guest_lib_dirs(rootfs)
    binds: list[tuple[str, str]] = []
    seen_guests: set[str] = set()

    # Scan all /usr/lib* directories on the host
    host_lib_dirs = set()
    for candidate in ("/usr/lib/x86_64-linux-gnu", "/usr/lib/i386-linux-gnu", "/usr/lib64", "/usr/lib32", "/usr/lib"):
        if os.path.isdir(candidate):
            host_lib_dirs.add(candidate)

    for lib_dir in sorted(host_lib_dirs):
        for pattern in _NVIDIA_LIB_PATTERNS:
            for lib_path in glob.glob(os.path.join(lib_dir, "**", pattern), recursive=True):
                if not os.path.isfile(lib_path):
                    continue

                # Never bind vendor-neutral GLVND dispatch libs: they belong
                # to the container's own Mesa/GLVND stack and shadowing them
                # corrupts its loader.
                if _is_glvnd_neutral(lib_path):
                    continue

                # Resolve symlinks to the actual file
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

                if guest_path in seen_guests:
                    continue
                seen_guests.add(guest_path)

                # Skip if guest already has this file (e.g. from a parent bind mount)
                guest_abs = os.path.join(rootfs, guest_path.lstrip("/"))
                if os.path.exists(guest_abs):
                    continue

                binds.append((real_path, guest_path))

    return binds


# ---------------------------------------------------------------------------
# WSL2-specific libraries
# ---------------------------------------------------------------------------


def find_wsl_libraries(rootfs: str) -> list[tuple[str, str]]:
    """Find WSL-specific NVIDIA/D3D12 libraries to bind-mount.

    On WSL2, the critical GPU libraries live under ``/usr/lib/wsl/lib/``
    and driver directories under ``/usr/lib/wsl/drivers/``. We bind the
    entire ``/usr/lib/wsl`` directory so both are accessible.
    """
    wsl_root = "/usr/lib/wsl"
    if not os.path.isdir(wsl_root):
        return []

    # Bind the entire WSL root directory
    return [(wsl_root, wsl_root)]


# ---------------------------------------------------------------------------
# Config / ICD / binary discovery
# ---------------------------------------------------------------------------


def find_nvidia_configs() -> list[tuple[str, str]]:
    """Find NVIDIA configuration and ICD descriptor files on the host.

    Returns ``(host_path, guest_path)`` pairs — guest paths equal host paths.
    """
    binds: list[tuple[str, str]] = []

    # 1. Generic nvidia config files in /etc/
    try:
        for root, _dirs, files in os.walk("/etc"):
            for fname in files:
                if "nvidia" in fname.lower():
                    full = os.path.join(root, fname)
                    if os.path.isfile(full):
                        binds.append((full, full))
    except OSError as exc:
        log.debug("Failed to search /etc for NVIDIA configuration files: %s", exc)

    # 2. Specific ICD/EGL/Vulkan config files
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

    Returns ``(host_path, guest_path)`` pairs.
    """
    binds: list[tuple[str, str]] = []
    search_dirs = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
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


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------


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
        # Native Linux with NVIDIA proprietary driver
        env["__NV_PRIME_RENDER_OFFLOAD"] = "1"
        env["__GLX_VENDOR_LIBRARY_NAME"] = "nvidia"

    return env


# ---------------------------------------------------------------------------
# ldconfig integration
# ---------------------------------------------------------------------------


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

    Uses ``chroot`` to execute ldconfig in the guest filesystem context.
    Non-fatal: logs on failure but does not raise.
    """
    ldconfig_path = os.path.join(rootfs, "sbin", "ldconfig")
    if not os.path.isfile(ldconfig_path):
        ldconfig_path = os.path.join(rootfs, "usr", "sbin", "ldconfig")
    if not os.path.isfile(ldconfig_path):
        log.debug("ldconfig not found in chroot, skipping cache refresh")
        return

    try:
        result = subprocess.run(
            ["chroot", rootfs, "/sbin/ldconfig"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            # Try alternate path
            result = subprocess.run(
                ["chroot", rootfs, "/usr/sbin/ldconfig"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        if result.returncode == 0:
            log.debug("ldconfig refreshed successfully in chroot")
        else:
            log.debug("ldconfig failed: %s", result.stderr.strip())
    except (subprocess.TimeoutExpired, OSError) as e:
        log.debug("ldconfig execution error: %s", e)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


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

    # 1. Device nodes
    binds.extend(find_nvidia_device_nodes())

    # 2. Libraries
    if is_wsl():
        wsl_binds = find_wsl_libraries(rootfs)
        binds.extend(wsl_binds)
        setup_ldconfig_for_wsl(rootfs)
    else:
        binds.extend(find_nvidia_libraries(rootfs))

    # 3. Config / ICD files
    binds.extend(find_nvidia_configs())

    # 4. Binaries (nvidia-smi, etc.)
    binds.extend(find_nvidia_binaries())

    # Deduplicate while preserving order
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
