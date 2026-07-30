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
    """On Android, mount usbfs at /dev/bus/usb if kernel + hardware support it.

    On regular Linux /dev/bus/usb comes in via the /dev bind — nothing to do.
    """
    if os.path.isdir("/dev/bus/usb"):
        return []  # already covered by the /dev bind

    if not IS_TERMUX:
        return []

    if not _fs_supported("usbfs"):
        log.debug("USB: kernel does not support usbfs, skipping")
        return []

    # No active USB host controller -> nothing to enumerate anyway.
    usb_sys = "/sys/bus/usb/devices"
    try:
        has_controller = any(e.startswith("usb") for e in os.listdir(usb_sys))
    except OSError:
        has_controller = False

    if not has_controller:
        log.debug("USB: no active USB host controller found in %s", usb_sys)
        return []

    # gid=5 is the "tty" group on Android; devmode=0664 gives group rw.
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


def _binfmt_misc_special(*, fresh_proc: bool = True) -> SpecialMount | None:
    """Mount binfmt_misc inside the chroot when the kernel supports it.

    The chroot's /proc is always a fresh procfs now, so the host's
    registrations are never inherited. *fresh_proc*=False keeps the legacy
    skip-if-host-has-it behaviour.
    """
    if not fresh_proc and os.path.exists("/proc/sys/fs/binfmt_misc/register"):
        return None  # host already has it; appears via the /proc bind

    if not _fs_supported("binfmt_misc"):
        log.debug("binfmt_misc: not in /proc/filesystems, skipping")
        return None

    return SpecialMount(
        fstype="binfmt_misc",
        source="binfmt_misc",
        target="/proc/sys/fs/binfmt_misc",
        options="",
        mkdir=False,  # the fresh procfs provides the binfmt_misc mountpoint stub
        check="binfmt_misc",
        optional=True,
    )


def _max_isolation_dev_specials() -> list[SpecialMount]:
    """Fresh tmpfs /dev for --isolated (host /dev is never bound there).

    The minimal device nodes, devpts and /dev/shm are added separately.
    """
    return [
        SpecialMount(
            fstype="tmpfs",
            source="tmpfs",
            target="/dev",
            options="mode=0755,size=64M",
            mkdir=True,
            optional=False,
        )
    ]


# (relative path, major, minor, mode) nodes for the fresh --isolated /dev.
MAX_ISOLATION_DEV_NODES: tuple[tuple[str, int, int, int], ...] = (
    ("null", 1, 3, 0o666),
    ("zero", 1, 5, 0o666),
    ("full", 1, 7, 0o666),
    ("random", 1, 8, 0o666),
    ("urandom", 1, 9, 0o666),
    ("tty", 5, 0, 0o666),
)


def get_special_mounts(
    rootfs: str,
    *,
    isolated: bool = False,
    max_isolation: bool = False,
    use_userns: bool = False,
    enable_usb: bool = True,
    enable_binfmt: bool = True,
    enable_shm: bool = True,
) -> list[SpecialMount]:
    """Return the special filesystem mounts to apply after bind mounts.

    No tmpfs is overmounted on /tmp or /run here — it would hide the display
    socket binds applied earlier. Under --isolated a fresh tmpfs /dev and a
    read-only sysfs replace the host binds.
    """
    specials: list[SpecialMount] = []

    if max_isolation:
        specials.extend(_max_isolation_dev_specials())

    # Fresh procfs in every mode (the host /proc is never bind-mounted);
    # hardened with hidepid=2 under max isolation. Without a PID namespace it
    # still shows the host's global PIDs.
    proc_options = "hidepid=2,nosuid,nodev,noexec" if max_isolation else ""
    specials.append(
        SpecialMount(
            fstype="proc",
            source="proc",
            target="/proc",
            options=proc_options,
            mkdir=True,
            check="proc",
            optional=False,
        )
    )

    # Max isolation: fresh read-only sysfs. Skipped under a user namespace —
    # the kernel EPERMs a fresh sysfs without an owned netns, so /sys comes
    # in as a recursive bind from get_bindings() instead.
    if max_isolation and not use_userns:
        specials.append(
            SpecialMount(
                fstype="sysfs",
                source="sysfs",
                target="/sys",
                options="ro,nosuid,nodev,noexec",
                mkdir=True,
                check="sysfs",
                optional=True,
            )
        )

    # Fresh `newinstance` devpts: on Android the on-disk /dev/pts nodes carry
    # the wrong device major, so glibc's ttyname() fails on the inherited pty
    # ("Inappropriate ioctl for device"). A fresh instance hands out ptys
    # with matching nodes; /dev/ptmx is pointed at it via bind_ptmx_to_pts().
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
        sm = _binfmt_misc_special(fresh_proc=True)
        if sm:
            specials.append(sm)

    # /dev/shm: always needed under max isolation (fresh /dev has none);
    # otherwise only when the host lacks one (some Android kernels).
    if enable_shm and (max_isolation or not os.path.exists("/dev/shm")):
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
            except OSError as exc:
                log.debug("File %s not readable, skipping binding: %s", real, exc)
    return binds


def best_effort_bind_sources() -> frozenset[str]:
    """Sources whose bind failure is non-fatal (warn + skip).

    Android integration extras only: some vendor kernels reject single binds
    (file bind -> EINVAL on 3.4), and losing these just degrades getprop,
    /sdcard etc. inside the guest.
    """
    srcs: set[str] = set()
    for fn in (dalvik_cache_bindings, storage_bindings, system_bindings, termux_app_bindings):
        srcs.update(src for src, _ in fn())
    return frozenset(srcs)


def get_bindings(
    rootfs: str,
    *,
    minimal: bool = False,
    isolated: bool = False,
    max_isolation: bool = False,
    use_namespaces: bool | None = None,
    use_userns: bool = False,
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

    # Default to *isolated* for backward compatibility when not passed.
    if use_namespaces is None:
        use_namespaces = isolated

    # Maximum isolation binds NOTHING from the host — even /dev and /sys are
    # escape vectors. The container relies entirely on the fresh
    # pseudo-filesystems from get_special_mounts().
    if max_isolation:
        # Exception: under a userns the kernel refuses a fresh sysfs, so /sys
        # is exposed as a recursive rslave bind of the host tree (the only
        # /sys mount the kernel permits here).
        if use_userns:
            try:
                sys_dst = resolve_rootfs_path(rootfs, "/sys")
            except OSError:
                sys_dst = os.path.join(rootfs, "sys")
            return ([("/sys", sys_dst)], [sys_dst])
        return ([], [])

    # 1. Base mounts. /proc is never bound — get_special_mounts() always
    # mounts a fresh procfs. The host /run is never bound either; with
    # --shared-display specific sockets are bound individually below.
    binds.append(("/dev", "/dev"))
    binds.append(("/sys", "/sys"))

    # Bind host /dev/pts but never /dev/ptmx (binding host ptmx leaked devpts
    # state and exhausted the host pty pool); the newinstance devpts in
    # get_special_mounts() provides the chroot's pty nodes.
    if os.path.exists("/dev/pts"):
        binds.append(("/dev/pts", "/dev/pts"))
    if os.path.exists("/dev/shm"):
        binds.append(("/dev/shm", "/dev/shm"))

    # Minimal mode: just the bare mounts.
    if minimal:
        return (
            [(src, os.path.join(rootfs, dst.lstrip("/"))) for src, dst in binds],
            [],
        )

    # 2. Android-specific bindings (system and storage)
    if IS_TERMUX and not isolated:
        # Parents (/data, TERMUX_PREFIX) MUST be bound before child paths:
        # a later parent mount shadows earlier children, making them
        # unreachable and breaking umount on cleanup.
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

        # Android system dirs (/apex, /system, /vendor, …) for BOTH dist
        # types: a termux-type guest ships fake /system stubs, but on a real
        # Android host it must see the device's real /system so termux-exec
        # and getprop work.
        for src, dst in system_bindings():
            binds.append((src, dst))

        # Termux app's private dirs. A termux-type guest ships its own
        # /data/data/com.termux and must never see the host's.
        if dist_type != "termux":
            for src, dst in termux_app_bindings():
                binds.append((src, dst))

    # 3. Shared home (--shared-home only, matches proot-distro).
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

    # 5a. Display runtime-dir bind (Linux + --shared-display): bind the
    # user's XDG_RUNTIME_DIR whole, recursively with rslave, so all session
    # sockets — including ones created after mount — stay visible.
    if not IS_TERMUX and shared_display and display_socket_binds:
        bound_srcs = {src for src, _ in binds}
        for path in display_socket_binds:
            if path not in bound_srcs and os.path.exists(path):
                binds.append((path, path))
                bound_srcs.add(path)
                if os.path.isdir(path):
                    rslave_targets.append(os.path.join(rootfs, path.lstrip("/")))

    # 5b. Display auth file binds (Linux only).
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

    # 7. User custom binds; they override system binds on destination
    # conflict (Docker/Podman --volume semantics).
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

            norm_dst = "/" + dst.strip("/")

            # Never override critical pseudo-filesystem mounts.
            if norm_dst in _critical_guest_paths or any(norm_dst.startswith(cp + "/") for cp in _critical_guest_paths):
                log.warning(
                    "Custom bind destination '%s' conflicts with critical system mount — ignoring. Cannot override %s.",
                    dst,
                    norm_dst,
                )
                continue

            # Drop system binds at or under the same destination.
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

    # Nest the guest target paths under the rootfs.
    resolved_binds = []
    for src, dst in binds:
        try:
            resolved_dst = resolve_rootfs_path(rootfs, dst)
        except OSError:
            resolved_dst = os.path.join(rootfs, dst.lstrip("/"))
        resolved_binds.append((src, resolved_dst))

    return resolved_binds, rslave_targets
