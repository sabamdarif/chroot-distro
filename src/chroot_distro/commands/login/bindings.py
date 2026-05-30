import logging
import os
from dataclasses import dataclass

from chroot_distro.commands.login.passwd import resolve_host_home
from chroot_distro.constants import (
    IS_TERMUX,
    TERMUX_APP_PACKAGE,
    TERMUX_HOME,
    TERMUX_PREFIX,
)

log = logging.getLogger(__name__)


@dataclass
class SpecialMount:
    """
    A non-bind-mount: mount -t <fstype> [-o <options>] <source> <target>.
    Used for usbfs, binfmt_misc, cgroup, devpts, tmpfs inside the chroot.
    """
    fstype: str           # e.g. "usbfs", "binfmt_misc", "cgroup", "tmpfs"
    source: str           # first arg, often "none" or same as fstype
    target: str           # absolute guest path (NOT yet prefixed with rootfs)
    options: str = ""     # -o value; empty string = no -o flag
    mkdir: bool = True    # create target dir inside rootfs if missing
    check: str = ""       # if set: verify this string is in /proc/filesystems first
    optional: bool = True # if True, log warning on failure instead of raising


def _fs_supported(fstype: str) -> bool:
    """Return True if the kernel reports support for the given filesystem type."""
    try:
        with open("/proc/filesystems") as f:
            return fstype in f.read()
    except OSError:
        return False


def _usb_specials() -> list[SpecialMount]:
    """On regular Linux: /dev/bus/usb already exists → comes in via /dev bind → nothing to do.

    On Android: mount usbfs at /dev/bus/usb if kernel + hardware support it.
    """
    # Regular Linux: /dev/bus/usb is a real directory created by udev
    if os.path.isdir("/dev/bus/usb"):
        return []  # already covered by existing /dev bind

    if not IS_TERMUX:
        return []

    # Android path: check kernel support
    if not _fs_supported("usbfs"):
        log.debug("USB: kernel does not support usbfs, skipping")
        return []

    # Check that at least one USB host controller is active (OTG host mode)
    # Without a host controller there are no devices to enumerate anyway
    usb_sys = "/sys/bus/usb/devices"
    try:
        has_controller = any(
            e.startswith("usb") for e in os.listdir(usb_sys)
        )
    except OSError:
        has_controller = False

    if not has_controller:
        log.debug("USB: no active USB host controller found in %s", usb_sys)
        return []

    # gid=5 is the "tty" group on Android; devmode=0664 gives group rw
    return [SpecialMount(
        fstype="usbfs",
        source="usbfs",
        target="/dev/bus/usb",
        options="devmode=0664,devgid=5",
        mkdir=True,
        check="usbfs",
        optional=True,
    )]


def _binfmt_misc_special() -> SpecialMount | None:
    """Mount binfmt_misc inside the chroot if the host hasn't already done it.

    On regular Linux with systemd: already mounted → comes in via /proc bind → return None.
    On Android: the kernel supports it but nothing mounts it → mount it ourselves.
    """
    # Already mounted? The 'register' file only appears when binfmt_misc is mounted.
    if os.path.exists("/proc/sys/fs/binfmt_misc/register"):
        return None  # host already has it; will appear in chroot via /proc bind

    if not _fs_supported("binfmt_misc"):
        log.debug("binfmt_misc: not in /proc/filesystems, skipping")
        return None

    return SpecialMount(
        fstype="binfmt_misc",
        source="binfmt_misc",
        target="/proc/sys/fs/binfmt_misc",
        options="",
        mkdir=False,   # /proc is already bind-mounted; the dir exists inside
        check="binfmt_misc",
        optional=True,
    )


def _docker_cgroup_specials() -> list[SpecialMount]:
    """Mount minimal cgroup controllers needed by Docker on Android.

    On regular Linux, these already exist under /sys/fs/cgroup/.
    """
    specials = []

    # On Android, the /sys/fs/cgroup directory is in the read-only sysfs.
    # We must mount a writeable tmpfs over /sys/fs/cgroup first, so that we can
    # create the controllers' mountpoint subdirectories.
    specials.append(SpecialMount(
        fstype="tmpfs",
        source="tmpfs",
        target="/sys/fs/cgroup",
        options="mode=0755",
        mkdir=True,
        optional=True,
    ))

    # Legacy cgroup devices controller
    # Required by Docker daemon to set up device access policies for containers
    if _fs_supported("cgroup"):    # NOTE: "cgroup" not "cgroup2"
        specials.append(SpecialMount(
            fstype="cgroup",
            source="cgroup",
            target="/sys/fs/cgroup/devices",
            options="devices",
            mkdir=True,
            check="cgroup",
            optional=True,
        ))

        # cpuset controller (required by many Docker networking setups)
        specials.append(SpecialMount(
            fstype="cgroup",
            source="cgroup",
            target="/sys/fs/cgroup/cpuset",
            options="cpuset",
            mkdir=True,
            check="cgroup",
            optional=True,
        ))

    return specials


def get_special_mounts(
    rootfs: str,
    *,
    enable_usb: bool = True,
    enable_binfmt: bool = True,
    enable_docker_cgroup: bool = True,   # enabled by default per user request
    enable_shm: bool = True,
) -> list[SpecialMount]:
    """Return list of special filesystem mounts to apply after bind mounts.

    Caller is responsible for actually running them via apply_special_mount().
    """
    specials: list[SpecialMount] = []

    # Devpts overmount to isolate chroot login session PTYs
    specials.append(SpecialMount(
        fstype="devpts",
        source="devpts",
        target="/dev/pts",
        options="gid=5,mode=620,ptmxmode=0666,newinstance",
        mkdir=True,
        check="devpts",
        optional=False,   # PTYs are required for a functional chroot login
    ))

    if enable_usb:
        specials.extend(_usb_specials())

    if enable_binfmt:
        sm = _binfmt_misc_special()
        if sm:
            specials.append(sm)

    if enable_docker_cgroup and IS_TERMUX:
        specials.extend(_docker_cgroup_specials())

    if enable_shm and not os.path.exists("/dev/shm"):
        # host already has /dev/shm → comes in via /dev bind
        # only add a fresh tmpfs when host doesn't have one (some Android kernels)
        specials.append(SpecialMount(
            fstype="tmpfs",
            source="tmpfs",
            target="/dev/shm",
            options="size=256M,mode=1777",
            mkdir=True,
            optional=True,
        ))

    return specials



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
    login_home: str = "/root",
    login_user: str = "root",
    dist_type: str = "normal",
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
        if os.path.isdir("/data"):
            binds.append(("/data", "/data"))
        for src, dst in system_bindings():
            binds.append((src, dst))
        for src, dst in storage_bindings():
            binds.append((src, dst))
        for src, dst in android_data_bindings():
            binds.append((src, dst))
        if os.path.exists(TERMUX_PREFIX):
            binds.append((TERMUX_PREFIX, TERMUX_PREFIX))

    # 3. Shared Home Directory
    # Only when --shared-home / --termux-home is set (matches proot-distro).
    host_home = resolve_host_home(login_user)

    should_share = shared_home
    if should_share:
        if IS_TERMUX and shared_home:
            if os.path.isdir(TERMUX_HOME) and login_home:
                binds.append((TERMUX_HOME, login_home))
        elif host_home and os.path.isdir(host_home) and login_home:
            binds.append((host_home, login_home))

    # 4. Shared Tmp
    if IS_TERMUX:
        if shared_tmp and dist_type != "termux":
            host_tmp = f"{TERMUX_PREFIX}/tmp"
            if os.path.exists(host_tmp):
                binds.append((host_tmp, "/tmp"))
    else:
        if (shared_tmp or not isolated) and os.path.exists("/tmp"):
            binds.append(("/tmp", "/tmp"))

    # 5. Shared X11 socket
    if IS_TERMUX:
        if shared_x11 and dist_type != "termux":
            host_x11 = f"{TERMUX_PREFIX}/tmp/.X11-unix"
            if os.path.exists(host_x11):
                binds.append((host_x11, "/tmp/.X11-unix"))
    else:
        if shared_x11 or not isolated:
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
