import os

from chroot_distro.constants import IS_TERMUX, TERMUX_APP_PACKAGE, TERMUX_PREFIX


def android_data_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for Android data paths (dalvik cache, app directories, etc.)."""
    binds: list[tuple[str, str]] = []
    if not IS_TERMUX:
        return binds

    for path in (
        "/data/app",
        "/data/dalvik-cache",
        "/data/misc/apexdata/com.android.art/dalvik-cache",
    ):
        try:
            real = os.path.realpath(path)
        except OSError:
            continue
        if not os.path.exists(real):
            continue
        if os.path.isdir(real):
            mode = oct(os.stat(real).st_mode)[-1]
            if mode in ("1", "5", "7"):
                binds.append((real, real))

    apps_dir = f"/data/data/{TERMUX_APP_PACKAGE}/files/apps"
    if os.path.isdir(apps_dir):
        binds.append((apps_dir, apps_dir))

    # Bind Termux cache directory
    cache_dir = f"/data/data/{TERMUX_APP_PACKAGE}/cache"
    if os.path.isdir(cache_dir):
        binds.append((cache_dir, cache_dir))

    return binds



def storage_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for Android shared storage."""
    binds: list[tuple[str, str]] = []
    if not IS_TERMUX:
        return binds

    if os.access("/storage", os.R_OK):
        binds.append(("/storage", "/storage"))
        if os.access("/storage/emulated/0", os.R_OK):
            binds.append(("/storage/emulated/0", "/sdcard"))
            binds.append(("/storage/emulated/0", "/mnt/sdcard"))
    else:
        for p in ("/storage/self/primary", "/storage/emulated/0", "/sdcard"):
            if os.access(p, os.R_OK):
                binds.extend([
                    (p, "/mnt/sdcard"),
                    (p, "/sdcard"),
                    (p, "/storage/emulated/0"),
                    (p, "/storage/self/primary"),
                ])
                break
    return binds


def system_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for Android system paths reachable by the guest."""
    binds: list[tuple[str, str]] = []
    if not IS_TERMUX:
        return binds

    for path in (
        "/apex", "/odm", "/product", "/system", "/system_ext", "/vendor",
        "/linkerconfig/ld.config.txt",
        "/linkerconfig/com.android.art/ld.config.txt",
        "/plat_property_contexts", "/property_contexts",
    ):
        try:
            real = os.path.realpath(path)
        except OSError:
            continue
        if not os.path.exists(real):
            continue
        if os.path.isdir(real):
            mode = oct(os.stat(real).st_mode)[-1]
            if mode in ("1", "5", "7"):
                binds.append((real, real))
        elif os.path.isfile(real):
            try:
                with open(real, "rb") as fh:
                    fh.read(1)
                binds.append((real, real))
            except OSError:
                pass
    return binds


def get_bindings(
    rootfs: str,
    *,
    minimal: bool = False,
    isolated: bool = False,
    shared_home: bool = False,
    shared_tmp: bool = False,
    shared_x11: bool = False,
    custom_binds: list[str] | None = None,
    login_home: str = "/root"
) -> list[tuple[str, str]]:
    """Assemble all (source, target_in_rootfs) bind mounts based on configurations."""
    binds = []

    # 1. Base Linux mounts (always needed for chroot to function correctly)
    # Target paths are absolute guest paths (e.g. /dev) which we will mount nested under rootfs.
    binds.append(("/dev", "/dev"))
    binds.append(("/proc", "/proc"))
    binds.append(("/sys", "/sys"))

    # Check if host /dev/pts and /dev/shm exist and mount them
    if os.path.exists("/dev/pts"):
        binds.append(("/dev/pts", "/dev/pts"))
    if os.path.exists("/dev/shm"):
        binds.append(("/dev/shm", "/dev/shm"))

    if os.path.exists("/run"):
        binds.append(("/run", "/run"))

    # If minimal mode is enabled, we only bind the bare systems (/dev, /proc, /sys, /run)
    if minimal:
        return [(src, os.path.join(rootfs, dst.lstrip("/"))) for src, dst in binds]

    # 2. Android-specific bindings (system and storage)
    if IS_TERMUX and not isolated:
        for src, dst in system_bindings():
            binds.append((src, dst))
        for src, dst in storage_bindings():
            binds.append((src, dst))
        for src, dst in android_data_bindings():
            binds.append((src, dst))
        if os.path.exists(TERMUX_PREFIX):
            binds.append((TERMUX_PREFIX, TERMUX_PREFIX))

    # 3. Shared Home Directory
    # Default behavior is sharing home in non-isolated/non-minimal mode, unless overridden.
    # If shared_home is explicitly requested, or if not isolated and running in standard mode.
    if shared_home or (not isolated and not IS_TERMUX):
        host_home = os.path.expanduser("~")
        if os.path.exists(host_home) and login_home:
            binds.append((host_home, login_home))

    # 4. Shared Tmp
    if (shared_tmp or (not isolated and not IS_TERMUX)) and os.path.exists("/tmp"):
        binds.append(("/tmp", "/tmp"))

    # 5. Shared X11 socket
    if shared_x11 or (not isolated and not IS_TERMUX):
        x11_path = "/tmp/.X11-unix"
        if os.path.exists(x11_path):
            binds.append((x11_path, x11_path))

    # 6. Custom binds specified by the user
    # Format: host_path:guest_path or host_path
    if custom_binds:
        for b in custom_binds:
            if ":" in b:
                src, dst = b.split(":", 1)
            else:
                src, dst = b, b
            if os.path.exists(src):
                binds.append((src, dst))

    # Map the guest target paths to be nested under rootfs absolute path
    resolved_binds = []
    for src, dst in binds:
        resolved_dst = os.path.join(rootfs, dst.lstrip("/"))
        resolved_binds.append((src, resolved_dst))

    return resolved_binds
