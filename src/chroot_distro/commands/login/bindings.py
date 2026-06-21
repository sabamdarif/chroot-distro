import logging
import os
from dataclasses import dataclass

from chroot_distro.commands.login.passwd import resolve_host_home, resolve_rootfs_path
from chroot_distro.constants import (
    IS_TERMUX,
    TERMUX_APP_PACKAGE,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
from chroot_distro.helpers import nvidia as nvidia_helper

log = logging.getLogger(__name__)


def _split_bind_spec(spec: str) -> tuple[str, str, str]:
    """Split a --bind spec into (host_src, guest_dst, options).

    Accepted forms:
      - ``/host``                       -> (/host, /host, "")
      - ``/host:/guest``                -> (/host, /guest, "")
      - ``/host:/guest:ro``             -> (/host, /guest, "ro")
      - ``/host:/guest:ro,nosuid``      -> (/host, /guest, "ro,nosuid")

    Only the first two colons are treated as field separators; everything
    after the second colon is the options field (commas separate options).
    """
    parts = spec.split(":", 2)
    if len(parts) == 1:
        return parts[0], parts[0], ""
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return parts[0], parts[1], parts[2]


def strip_bind_options(custom_binds: list[str] | None) -> list[str]:
    """Return *custom_binds* as ``host:guest`` specs with options removed.

    get_bindings() only understands ``host`` or ``host:guest`` and splits on
    the first colon, so the third options field must be stripped before the
    specs are passed to it.
    """
    if not custom_binds:
        return []
    stripped: list[str] = []
    for spec in custom_binds:
        src, dst, _opts = _split_bind_spec(spec)
        stripped.append(f"{src}:{dst}" if dst != src else src)
    return stripped


def parse_bind_options(custom_binds: list[str] | None) -> dict[str, str]:
    """Map normalized guest destination path -> mount options string.

    Only entries that actually specify options are included. The guest path
    is normalized to a leading-slash, no-trailing-slash form so it can be
    matched against resolved bind targets by the caller.
    """
    options_map: dict[str, str] = {}
    if not custom_binds:
        return options_map
    for spec in custom_binds:
        _src, dst, opts = _split_bind_spec(spec)
        if not opts:
            continue
        norm_dst = "/" + dst.strip("/")
        options_map[norm_dst] = opts
    return options_map


@dataclass
class SpecialMount:
    """
    A non-bind-mount: mount -t <fstype> [-o <options>] <source> <target>.
    Used for usbfs, binfmt_misc, cgroup, devpts, tmpfs inside the chroot.
    """

    fstype: str  # e.g. "usbfs", "binfmt_misc", "cgroup", "tmpfs"
    source: str  # first arg, often "none" or same as fstype
    target: str  # absolute guest path (NOT yet prefixed with rootfs)
    options: str = ""  # -o value; empty string = no -o flag
    mkdir: bool = True  # create target dir inside rootfs if missing
    check: str = ""  # if set: verify this string is in /proc/filesystems first
    optional: bool = True  # if True, log warning on failure instead of raising


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
        has_controller = any(e.startswith("usb") for e in os.listdir(usb_sys))
    except OSError:
        has_controller = False

    if not has_controller:
        log.debug("USB: no active USB host controller found in %s", usb_sys)
        return []

    # gid=5 is the "tty" group on Android; devmode=0664 gives group rw
    return [
        SpecialMount(
            fstype="usbfs",
            source="usbfs",
            target="/dev/bus/usb",
            options="devmode=0664,devgid=5",
            mkdir=True,
            check="usbfs",
            optional=True,
        )
    ]


def _binfmt_misc_special(*, fresh_proc: bool = False) -> SpecialMount | None:
    """Mount binfmt_misc inside the chroot if the host hasn't already done it.

    On regular Linux with systemd: already mounted → comes in via /proc bind → return None.
    On Android: the kernel supports it but nothing mounts it → mount it ourselves.

    When *fresh_proc* is True (--isolated), /proc is a new procfs mount in the PID
    namespace, so binfmt_misc must be mounted explicitly when supported.
    """
    # Already mounted? The 'register' file only appears when binfmt_misc is mounted.
    if not fresh_proc and os.path.exists("/proc/sys/fs/binfmt_misc/register"):
        return None  # host already has it; will appear in chroot via /proc bind

    if not _fs_supported("binfmt_misc"):
        log.debug("binfmt_misc: not in /proc/filesystems, skipping")
        return None

    return SpecialMount(
        fstype="binfmt_misc",
        source="binfmt_misc",
        target="/proc/sys/fs/binfmt_misc",
        options="",
        mkdir=False,  # /proc is already bind-mounted; the dir exists inside
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
    specials.append(
        SpecialMount(
            fstype="tmpfs",
            source="tmpfs",
            target="/sys/fs/cgroup",
            options="mode=0755",
            mkdir=True,
            optional=True,
        )
    )

    # Legacy cgroup devices controller
    # Required by Docker daemon to set up device access policies for containers
    if _fs_supported("cgroup"):  # NOTE: "cgroup" not "cgroup2"
        specials.append(
            SpecialMount(
                fstype="cgroup",
                source="cgroup",
                target="/sys/fs/cgroup/devices",
                options="devices",
                mkdir=True,
                check="cgroup",
                optional=True,
            )
        )

        # cpuset controller (required by many Docker networking setups)
        specials.append(
            SpecialMount(
                fstype="cgroup",
                source="cgroup",
                target="/sys/fs/cgroup/cpuset",
                options="cpuset",
                mkdir=True,
                check="cgroup",
                optional=True,
            )
        )

    return specials


def get_special_mounts(
    rootfs: str,
    *,
    isolated: bool = False,
    enable_usb: bool = True,
    enable_binfmt: bool = True,
    enable_docker_cgroup: bool = True,  # enabled by default per user request
    enable_shm: bool = True,
) -> list[SpecialMount]:
    """Return list of special filesystem mounts to apply after bind mounts.

    Caller is responsible for actually running them via apply_special_mount().

    Note on /tmp and /run isolation: these are NOT bind-mounted from the
    host by default (see get_bindings()), so the container falls back to its
    own empty, writable /tmp and /run directories. No tmpfs overmount is
    used here because it would mount on top of the display socket and
    /tmp/.X11-unix binds applied earlier, hiding them.
    """
    specials: list[SpecialMount] = []

    # PID-namespace-aware procfs (must not bind-mount host /proc when isolated).
    if isolated:
        specials.append(
            SpecialMount(
                fstype="proc",
                source="proc",
                target="/proc",
                options="",
                mkdir=True,
                check="proc",
                optional=False,
            )
        )

    # Devpts handling.
    #
    # Termux/Android: the on-disk /dev/pts/N nodes carry device major 88 while
    # the live ptys the kernel hands out use major 136. glibc's ttyname()
    # matches fd 0's st_rdev against /dev/pts entries, so the inherited login
    # pty never matches -> "tty: ttyname error: Inappropriate ioctl for
    # device". Mount a *fresh* `newinstance` devpts so newly allocated ptys get
    # the correct major and a matching /dev/pts/N node; the inner login is then
    # run under a pty allocator (see login) so it acquires one of these new
    # ptys as its controlling terminal. /dev/ptmx is pointed at this instance
    # in login via bind_ptmx_to_pts().
    #
    # Devpts overmount to isolate chroot login session PTYs.
    specials.append(
        SpecialMount(
            fstype="devpts",
            source="devpts",
            target="/dev/pts",
            options="gid=5,mode=620,ptmxmode=0666,newinstance",
            mkdir=True,
            check="devpts",
            optional=False,  # PTYs are required for a functional chroot login
        )
    )

    if enable_usb:
        specials.extend(_usb_specials())

    if enable_binfmt:
        sm = _binfmt_misc_special(fresh_proc=isolated)
        if sm:
            specials.append(sm)

    if enable_docker_cgroup and IS_TERMUX:
        specials.extend(_docker_cgroup_specials())

    if enable_shm and not os.path.exists("/dev/shm"):
        # host already has /dev/shm → comes in via /dev bind
        # only add a fresh tmpfs when host doesn't have one (some Android kernels)
        specials.append(
            SpecialMount(
                fstype="tmpfs",
                source="tmpfs",
                target="/dev/shm",
                options="size=256M,mode=1777",
                mkdir=True,
                optional=True,
            )
        )

    return specials


def dalvik_cache_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for host Android Dalvik/ART caches.

    These are Android-system caches, not the Termux app's private data,
    so both normal-type and termux-type guests get them.
    """
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
    return binds


def termux_app_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for Termux app private directories.

    Normal-type containers only: a termux-type guest must not see the
    host's /data/data/com.termux, so this is never called for it.
    """
    binds: list[tuple[str, str]] = []
    if not IS_TERMUX:
        return binds

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
                binds.extend(
                    [
                        (p, "/mnt/sdcard"),
                        (p, "/sdcard"),
                        (p, "/storage/emulated/0"),
                        (p, "/storage/self/primary"),
                    ]
                )
                break
    return binds


def system_bindings() -> list[tuple[str, str]]:
    """Return list of (source, target) tuples for Android system paths reachable by the guest."""
    binds: list[tuple[str, str]] = []
    if not IS_TERMUX:
        return binds

    for path in (
        "/apex",
        "/odm",
        "/product",
        "/system",
        "/system_ext",
        "/vendor",
        "/linkerconfig/ld.config.txt",
        "/linkerconfig/com.android.art/ld.config.txt",
        "/plat_property_contexts",
        "/property_contexts",
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
    use_namespaces: bool | None = None,
    shared_home: bool = False,
    shared_tmp: bool = False,
    shared_display: bool = False,
    display_auth_binds: list[str] | None = None,
    display_socket_binds: list[str] | None = None,
    custom_binds: list[str] | None = None,
    login_home: str = "/root",
    login_user: str = "root",
    dist_type: str = "normal",
    nvidia_integration: bool = False,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Assemble all (source, target_in_rootfs) bind mounts based on configurations.

    Returns:
        (resolved_binds, rslave_targets) — rslave_targets lists absolute
        guest paths that should get ``mount --make-rslave`` after binding.
    """
    binds = []
    rslave_targets: list[str] = []

    # When namespaces are active, a fresh procfs is mounted in the PID
    # namespace by get_special_mounts(). CD_USE_NS keeps every other mount
    # (isolated=False) but still namespaces PIDs, so the /proc decision must
    # follow namespace use, not the mount-skipping flag. Default to *isolated*
    # for backward compatibility when the caller does not pass it explicitly.
    if use_namespaces is None:
        use_namespaces = isolated

    # 1. Base Linux mounts (always needed for chroot to function correctly)
    # Target paths are absolute guest paths (e.g. /dev) which we will mount nested under rootfs.
    binds.append(("/dev", "/dev"))
    # Host /proc bind breaks PID namespace isolation; mount procfs in get_special_mounts().
    if not use_namespaces:
        binds.append(("/proc", "/proc"))
    binds.append(("/sys", "/sys"))

    # Check if host /dev/pts and /dev/shm exist and mount them. We bind the
    # host /dev/pts (matching pre-v2.1.2 behaviour) but never the host
    # /dev/ptmx: binding the host /dev/ptmx leaked devpts state and exhausted
    # the host pty pool. The newinstance devpts overmount in
    # get_special_mounts() provides the chroot's pty nodes.
    if os.path.exists("/dev/pts"):
        binds.append(("/dev/pts", "/dev/pts"))
    if os.path.exists("/dev/shm"):
        binds.append(("/dev/shm", "/dev/shm"))

    # /run handling.
    #
    # The host's /run is NEVER bound: the container uses its own (empty)
    # /run directory, so it cannot see the host's runtime sockets
    # (PulseAudio, D-Bus, systemd, NetworkManager, ...). With
    # --shared-display the specific display/audio/D-Bus sockets are bound
    # individually into /run/user/<uid>/ via display_socket_binds below.

    # If minimal mode is enabled, we only bind the bare systems (/dev, /proc, /sys)
    if minimal:
        return (
            [(src, os.path.join(rootfs, dst.lstrip("/"))) for src, dst in binds],
            [],
        )

    # 2. Android-specific bindings (system and storage)
    if IS_TERMUX and not isolated:
        # Parent directories (/data, TERMUX_PREFIX) MUST be bound before any
        # child paths (dalvik caches, termux app dirs, etc.). If a child bind
        # is applied first and the parent is bound afterwards, the parent mount
        # shadows the child — the kernel still tracks the child mount in
        # /proc/mounts but it becomes unreachable, so umount fails with
        # "not mounted" on cleanup.
        if dist_type != "termux":
            if os.path.isdir("/data"):
                binds.append(("/data", "/data"))
            if os.path.exists(TERMUX_PREFIX):
                binds.append((TERMUX_PREFIX, TERMUX_PREFIX))

        # Dalvik/ART caches and shared storage are host-domain Android
        # paths bound for both distro types in the default mode.
        for src, dst in dalvik_cache_bindings():
            binds.append((src, dst))
        for src, dst in storage_bindings():
            binds.append((src, dst))

        # Android system directories (/apex, /system, /vendor, …). Bound only for normal-type.
        if dist_type != "termux":
            for src, dst in system_bindings():
                binds.append((src, dst))

        # Termux app's private dirs. A termux-type guest ships its own
        # /data/data/com.termux and must never see the host's.
        if dist_type != "termux":
            for src, dst in termux_app_bindings():
                binds.append((src, dst))

    # 3. Shared Home Directory
    # Only when --shared-home is set (matches proot-distro).
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
        # /tmp defaults to a fresh tmpfs (get_special_mounts); bind the host
        # /tmp only when the user explicitly opts in with --shared-tmp.
        if shared_tmp and os.path.exists("/tmp"):
            binds.append(("/tmp", "/tmp"))

    # 5. Display sharing (X11 + Wayland + Sound + D-Bus)
    if IS_TERMUX:
        if shared_display and dist_type != "termux":
            host_x11 = f"{TERMUX_PREFIX}/tmp/.X11-unix"
            if os.path.exists(host_x11):
                binds.append((host_x11, "/tmp/.X11-unix"))
    else:
        if shared_display:
            x11_path = "/tmp/.X11-unix"
            if os.path.exists(x11_path):
                binds.append((x11_path, x11_path))

    # 5a. Display runtime-dir bind (Linux + --shared-display): the host's
    # broad /run is not bound, so bind the user's XDG_RUNTIME_DIR
    # (/run/user/<uid>) whole. It is mounted recursively with rslave
    # (see rslave_targets) so it keeps the host directory ownership and all
    # session sockets (Wayland, PulseAudio, PipeWire, D-Bus), and new
    # sockets created after mount stay visible.
    if not IS_TERMUX and shared_display and display_socket_binds:
        bound_srcs = {src for src, _ in binds}
        for path in display_socket_binds:
            if path not in bound_srcs and os.path.exists(path):
                binds.append((path, path))
                bound_srcs.add(path)
                if os.path.isdir(path):
                    rslave_targets.append(os.path.join(rootfs, path.lstrip("/")))

    # 5b. Display auth file binds (Linux only). When /run is bound whole the
    # runtime dir is already covered; when narrowed, socket binds above
    # include the runtime dir, so auth files under it are covered too.
    if not IS_TERMUX and shared_display and display_auth_binds:
        bound_srcs = {src for src, _ in binds}
        for path in display_auth_binds:
            if os.path.exists(path) and path not in bound_srcs:
                binds.append((path, path))
                bound_srcs.add(path)

    # 6. NVIDIA GPU integration (device nodes, libraries, configs, binaries)
    if nvidia_integration:
        nvidia_binds, _nvidia_env = nvidia_helper.get_nvidia_integration(rootfs)
        bound_srcs = {src for src, _ in binds}
        for src, dst in nvidia_binds:
            if src not in bound_srcs and os.path.exists(src):
                binds.append((src, dst))
                bound_srcs.add(src)

    # 7. Custom binds specified by the user
    # Format: host_path:guest_path or host_path
    # Custom binds override system binds when the destination conflicts
    # (matches Docker/Podman --volume semantics).
    _critical_guest_paths = frozenset({"/dev", "/proc", "/sys"})

    if custom_binds:
        for b in custom_binds:
            if ":" in b:
                src, dst = b.split(":", 1)
            else:
                src, dst = b, b

            if not os.path.exists(src):
                log.warning("Custom bind source does not exist: %s (skipping)", src)
                continue

            # Normalize destination for comparison
            norm_dst = "/" + dst.strip("/")

            # Block overrides of critical pseudo-filesystem mounts
            if norm_dst in _critical_guest_paths or any(norm_dst.startswith(cp + "/") for cp in _critical_guest_paths):
                log.warning(
                    "Custom bind destination '%s' conflicts with critical system mount — ignoring. Cannot override %s.",
                    dst,
                    norm_dst,
                )
                continue

            # Remove any system bind with the same destination or nested under it (user override wins)
            prev_len = len(binds)
            binds = [
                (s, d)
                for s, d in binds
                if ("/" + d.strip("/")) != norm_dst and not ("/" + d.strip("/")).startswith(norm_dst + "/")
            ]
            if len(binds) < prev_len:
                log.info(
                    "Custom bind '%s:%s' overrides default system mount for '%s'",
                    src,
                    dst,
                    norm_dst,
                )

            binds.append((src, dst))

    # Map the guest target paths to be nested under rootfs absolute path
    resolved_binds = []
    for src, dst in binds:
        try:
            resolved_dst = resolve_rootfs_path(rootfs, dst)
        except OSError:
            resolved_dst = os.path.join(rootfs, dst.lstrip("/"))
        resolved_binds.append((src, resolved_dst))

    return resolved_binds, rslave_targets
