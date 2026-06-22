import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field

from chroot_distro.arch import detect_installed_arch, get_device_cpu_arch, supports_32bit
from chroot_distro.commands.list_cmd import (
    _ensure_manifest_readable,
    _iter_container_names,
    _read_image_source,
    _rootfs_size_bytes,
)
from chroot_distro.commands.kernel_config import (
    CONFIG_BUILTIN,
    CONFIG_MISSING,
    CONFIG_MODULE,
    CONFIG_UNKNOWN,
    KERNEL_FLAG_GROUPS,
    find_kernel_config,
    lookup_flag,
    parse_kernel_config,
)
from chroot_distro.constants import (
    BASE_CACHE_DIR,
    CANONICAL_PROGRAM_NAME,
    IS_TERMUX,
    LAYER_CACHE_DIR,
    MANIFEST_CACHE_DIR,
    PROGRAM_NAME,
    PROGRAM_VERSION,
    RUNTIME_DIR,
    TERMUX_APP_PACKAGE,
)
from chroot_distro.locking import container_busy_status
from chroot_distro.message import C, msg
from chroot_distro.paths import container_manifest, container_rootfs
from chroot_distro.progress import fmt_size, loading_line

_NA = "unknown"

# Marker glyphs reused across capability + analysis rendering.
_OK = "\u2714"  # heavy check mark
_BAD = "\u2718"  # heavy ballot X
_WARN = "\u26a0"  # warning sign


@dataclass(frozen=True)
class _HostInfo:
    """Platform facts shared by Termux/Android and regular Linux hosts."""

    kind: str  # "Termux / Android" or "Linux"
    fields: list[tuple[str, str]]


@dataclass
class _Capability:
    """A single host capability check result for the report.

    ``level`` is one of "ok", "warn", "bad", or "info" and drives the glyph
    and color used when rendering.
    """

    label: str
    value: str
    level: str = "info"


@dataclass
class _ImageInfo:
    """Per-container facts plus any analysis findings."""

    name: str
    size: str = "?"
    size_bytes: int = 0
    arch: str = _NA
    source: str = _NA
    status: str = _NA
    source_url: str = ""
    image_type: str = ""
    findings: list[str] = field(default_factory=list)


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release into a dict, tolerating missing files."""
    data: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip().strip('"').strip("'")
            if data:
                return data
        except OSError:
            continue
    return data


def _read_build_prop(keys: tuple[str, ...]) -> dict[str, str]:
    """Read selected getprop-style keys from Android, falling back to file."""
    found: dict[str, str] = {}
    try:
        out = subprocess.check_output(["getprop"], stderr=subprocess.DEVNULL, text=True, timeout=5)
        for line in out.splitlines():
            # Format: [key]: [value]
            if "]: [" not in line:
                continue
            key, _, value = line.partition("]: [")
            key = key.lstrip("[").strip()
            value = value.rstrip("]").strip()
            if key in keys and value:
                found[key] = value
    except (OSError, subprocess.SubprocessError):
        pass
    if all(k in found for k in keys):
        return found
    try:
        with open("/system/build.prop", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key in keys and key not in found and value.strip():
                    found[key] = value.strip()
    except OSError:
        pass
    return found


def _termux_host_info() -> _HostInfo:
    """Collect Termux app + Android OS facts."""
    fields: list[tuple[str, str]] = []

    termux_version = os.environ.get("TERMUX_APP__APP_VERSION_NAME") or os.environ.get("TERMUX_VERSION") or _NA
    fields.append(("Termux version", termux_version))
    fields.append(("Termux package", TERMUX_APP_PACKAGE))

    props = _read_build_prop(
        (
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.product.manufacturer",
            "ro.product.model",
            "ro.product.device",
        )
    )
    android_release = props.get("ro.build.version.release", _NA)
    android_sdk = props.get("ro.build.version.sdk", "")
    android_label = android_release
    if android_sdk:
        android_label = f"{android_release} (API {android_sdk})"
    fields.append(("Android version", android_label))

    manufacturer = props.get("ro.product.manufacturer", "")
    model = props.get("ro.product.model", "")
    device = props.get("ro.product.device", "")
    device_label = " ".join(p for p in (manufacturer, model) if p) or _NA
    if device and device not in device_label:
        device_label = f"{device_label} ({device})"
    fields.append(("Device", device_label))

    fields.append(("Kernel", platform.release() or _NA))
    return _HostInfo(kind="Termux / Android", fields=fields)


def _linux_host_info() -> _HostInfo:
    """Collect regular Linux distribution + kernel facts."""
    fields: list[tuple[str, str]] = []
    os_release = _read_os_release()

    pretty = os_release.get("PRETTY_NAME", "")
    if not pretty:
        name = os_release.get("NAME", "")
        version = os_release.get("VERSION", os_release.get("VERSION_ID", ""))
        pretty = " ".join(p for p in (name, version) if p)
    fields.append(("Distribution", pretty or _NA))

    version_id = os_release.get("VERSION_ID", "")
    if version_id:
        fields.append(("Version", version_id))

    fields.append(("Kernel", platform.release() or _NA))
    fields.append(("Platform", platform.platform() or _NA))
    libc_name, libc_version = platform.libc_ver()
    if libc_name:
        fields.append(("libc", f"{libc_name} {libc_version}".strip()))
    return _HostInfo(kind="Linux", fields=fields)


def _gather_host_info() -> _HostInfo:
    return _termux_host_info() if IS_TERMUX else _linux_host_info()


def _detect_escalation_tool() -> str:
    """Return the name of the first available privilege-escalation tool, or ''."""
    for tool in ("sudo", "doas", "pkexec", "su"):
        if shutil.which(tool):
            return tool
    return ""


def _data_mount_flags() -> tuple[str, str]:
    """Return (options, level) describing Termux /data suid/exec flags."""
    from chroot_distro.helpers.android import _read_data_mount

    entry = _read_data_mount()
    if not entry:
        return "not found in /proc/mounts", "warn"
    _device, _mount, opts = entry
    problems = [flag for flag in ("nosuid", "noexec") if flag in opts]
    if problems:
        return f"{opts} ({', '.join(problems)} breaks sudo/apt)", "warn"
    return opts, "ok"


def _binfmt_qemu_status(needs_emulation: bool) -> tuple[str, str]:
    """Return (value, level) describing binfmt_misc + QEMU availability."""
    binfmt_dir = "/proc/sys/fs/binfmt_misc"
    if not os.path.isdir(binfmt_dir):
        value = "binfmt_misc not mounted"
        return value, ("bad" if needs_emulation else "info")
    qemu_handlers: list[str] = []
    try:
        for entry in sorted(os.listdir(binfmt_dir)):
            if entry.startswith("qemu-"):
                qemu_handlers.append(entry[len("qemu-") :])
    except OSError:
        pass
    if qemu_handlers:
        return f"binfmt_misc + qemu ({', '.join(qemu_handlers)})", "ok"
    value = "binfmt_misc mounted, no qemu handler registered"
    return value, ("bad" if needs_emulation else "info")


def _userns_enabled() -> bool | None:
    """Return True/False if user-namespace support is known, else None."""
    path = "/proc/sys/user/max_user_namespaces"
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip()) > 0
    except (OSError, ValueError):
        return None


def _namespace_status() -> tuple[str, str]:
    """Return (value, level) describing unshare/nsenter + userns support."""
    tools = [t for t in ("unshare", "nsenter") if shutil.which(t)]
    if not tools:
        return "unshare/nsenter not found (--isolated unavailable)", "warn"
    userns = _userns_enabled()
    if userns is False:
        return f"{'+'.join(tools)} present, user namespaces disabled", "warn"
    if userns is None:
        return f"{'+'.join(tools)} present", "ok"
    return f"{'+'.join(tools)} present, user namespaces enabled", "ok"


def _free_disk(path: str) -> tuple[str, str]:
    """Return (value, level) for free space on the filesystem holding *path*."""
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        usage = shutil.disk_usage(probe or "/")
    except OSError:
        return _NA, "info"
    free_pct = (usage.free * 100 // usage.total) if usage.total else 0
    value = f"{fmt_size(usage.free)} free of {fmt_size(usage.total)} ({free_pct}%)"
    level = "warn" if usage.free < (1 << 30) else "info"  # < 1 GiB free
    return value, level


def _dir_size_bytes(path: str) -> int:
    """Return total file size under *path*, ignoring unreadable entries."""
    total = 0
    for dirpath, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                continue
    return total


def _cache_size() -> tuple[str, str]:
    """Return (value, level) describing the OCI layer + manifest cache size."""
    seen: set[str] = set()
    total = 0
    for cache_dir in (LAYER_CACHE_DIR, MANIFEST_CACHE_DIR, BASE_CACHE_DIR):
        real = os.path.realpath(cache_dir)
        if real in seen or not os.path.isdir(cache_dir):
            continue
        seen.add(real)
        total += _dir_size_bytes(cache_dir)
    if total == 0:
        return "empty", "info"
    return f"{fmt_size(total)} (clear with '{PROGRAM_NAME} clear-cache')", "info"


def _lsm_status() -> tuple[str, str] | None:
    """Return (value, level) for SELinux/AppArmor mode on Linux, or None."""
    # SELinux: /sys/fs/selinux/enforce -> 1 enforcing, 0 permissive.
    enforce_path = "/sys/fs/selinux/enforce"
    if os.path.exists(enforce_path):
        try:
            with open(enforce_path, encoding="utf-8") as fh:
                mode = "enforcing" if fh.read().strip() == "1" else "permissive"
        except OSError:
            mode = "present"
        return f"SELinux {mode}", ("warn" if mode == "enforcing" else "info")
    # AppArmor: presence of the sysfs module dir.
    if os.path.isdir("/sys/module/apparmor") or os.path.exists("/sys/kernel/security/apparmor/profiles"):
        return "AppArmor enabled", "info"
    return None


def _gather_capabilities(images: list["_ImageInfo"], host_arch: str) -> list[_Capability]:
    """Collect host capability checks relevant to launching containers."""
    caps: list[_Capability] = []

    is_root = os.getuid() == 0
    tool = _detect_escalation_tool()
    if is_root:
        caps.append(_Capability("Privileges", "running as root", "ok"))
    elif tool:
        caps.append(_Capability("Privileges", f"not root, can elevate via {tool}", "info"))
    else:
        caps.append(_Capability("Privileges", "not root, no sudo/doas/pkexec/su found", "bad"))

    if IS_TERMUX:
        value, level = _data_mount_flags()
        caps.append(_Capability("/data mount", value, level))

    needs_emulation = any("needs emulation" in f for img in images for f in img.findings)
    binfmt_value, binfmt_level = _binfmt_qemu_status(needs_emulation)
    caps.append(_Capability("Foreign arch", binfmt_value, binfmt_level))

    ns_value, ns_level = _namespace_status()
    caps.append(_Capability("Namespaces", ns_value, ns_level))

    if not IS_TERMUX:
        lsm = _lsm_status()
        if lsm:
            caps.append(_Capability("Security module", lsm[0], lsm[1]))

    disk_value, disk_level = _free_disk(RUNTIME_DIR)
    caps.append(_Capability("Disk (data dir)", disk_value, disk_level))

    cache_value, cache_level = _cache_size()
    caps.append(_Capability("Download cache", cache_value, cache_level))

    return caps


def _read_manifest_labels(name: str) -> tuple[str, str]:
    """Return (source_url, image_type) from the manifest config labels."""
    manifest_path = container_manifest(name)
    if not os.path.isfile(manifest_path):
        return "", ""
    _ensure_manifest_readable(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            data = json.loads(fh.read() or "{}")
    except (OSError, json.JSONDecodeError):
        return "", ""
    cfg = (data.get("image_config") or {}).get("config") or {}
    labels = cfg.get("Labels") or {}
    return (
        labels.get("org.opencontainers.image.source", ""),
        labels.get("IMAGE_TYPE", ""),
    )


def _has_rootfs_structure(rootfs: str) -> bool:
    """Return True when *rootfs* looks like a real root filesystem.

    A valid rootfs has at least one of the common top-level directories.
    Distroless/minimal images may omit /etc entirely, so this stays lenient.
    """
    return any(os.path.isdir(os.path.join(rootfs, entry)) for entry in ("bin", "usr", "sbin", "lib", "etc", "system"))


def _analyze_image(info: _ImageInfo, host_arch: str) -> None:
    """Populate findings that help spot why an image may misbehave."""
    rootfs = container_rootfs(info.name)

    if not os.path.isfile(container_manifest(info.name)):
        info.findings.append("no manifest.json (reset/diff/run unavailable)")

    if info.size_bytes == 0:
        info.findings.append("rootfs is empty (install may be incomplete)")
    elif info.arch in (_NA, "") and not _has_rootfs_structure(rootfs):
        # Only flag when nothing identifies this as a usable rootfs: arch
        # detection found no ELF binary and none of the common top-level
        # directories exist. Minimal/distroless images (e.g. termux-docker)
        # legitimately lack /etc/os-release and /etc/passwd, so their presence
        # is no longer required.
        info.findings.append("no recognizable rootfs layout (install may be incomplete)")

    if (
        info.arch not in (_NA, "")
        and host_arch not in (_NA, "")
        and info.arch != host_arch
        and not (host_arch in ("x86_64", "aarch64") and info.arch in ("i686", "arm"))
    ):
        info.findings.append(f"arch '{info.arch}' differs from host '{host_arch}' (needs emulation)")


def _gather_images(host_arch: str) -> list[_ImageInfo]:
    names = _iter_container_names()
    images: list[_ImageInfo] = []
    total = len(names)
    with loading_line("Gathering image info...") as update:
        for index, name in enumerate(names, start=1):
            update(f"Scanning {name} ({index}/{total})...")
            info = _ImageInfo(name=name)
            try:
                info.size_bytes = _rootfs_size_bytes(container_rootfs(name))
                info.size = fmt_size(info.size_bytes)
            except OSError:
                info.size = "?"
            info.arch = detect_installed_arch(name)
            info.source = _read_image_source(name)
            info.status = container_busy_status(name)
            info.source_url, info.image_type = _read_manifest_labels(name)
            _analyze_image(info, host_arch)
            images.append(info)
    return images


def _kv(label: str, value: str, label_w: int) -> str:
    return f"  {C['CYAN']}{label + ':':<{label_w}}{C['RST']} {C['WHITE']}{value}{C['RST']}"


def _render_section(title: str) -> None:
    msg()
    msg(f"{C['UBCYAN']}{title}{C['RST']}")
    msg()


def _render_basic() -> None:
    label_w = 16
    _render_section(f"{CANONICAL_PROGRAM_NAME}")
    msg(_kv("Program", PROGRAM_NAME, label_w))
    msg(_kv("Version", PROGRAM_VERSION, label_w))
    msg(_kv("Python", platform.python_version(), label_w))
    msg(_kv("Data location", RUNTIME_DIR, label_w))


def _render_host(host: _HostInfo, host_arch: str) -> None:
    label_w = 16
    _render_section("HOST")
    msg(_kv("Type", host.kind, label_w))
    arch_value = host_arch
    if host_arch in ("aarch64", "x86_64"):
        arch_value = f"{host_arch} ({'supports' if supports_32bit() else 'no'} 32-bit)"
    msg(_kv("Architecture", arch_value, label_w))
    for label, value in host.fields:
        msg(_kv(label, value, label_w))


def _format_image_table(images: list[_ImageInfo]) -> list[str]:
    name_w = max(len("NAME"), *(len(i.name) for i in images))
    size_w = max(len("SIZE"), *(len(i.size) for i in images))
    arch_w = max(len("ARCH"), *(len(i.arch) for i in images))
    source_w = max(len("SOURCE"), *(len(i.source) for i in images))
    status_w = max(len("STATUS"), *(len(i.status) for i in images))

    lines = [
        f"  {C['BCYAN']}{'NAME':<{name_w}}  {'SIZE':>{size_w}}  "
        f"{'ARCH':<{arch_w}}  {'SOURCE':<{source_w}}  {'STATUS':<{status_w}}{C['RST']}",
    ]
    for img in images:
        status_color = "YELLOW" if img.status.startswith("in use") else "GREEN"
        lines.append(
            f"  {C['GREEN']}{img.name:<{name_w}}{C['RST']}  "
            f"{C['CYAN']}{img.size:>{size_w}}{C['RST']}  "
            f"{img.arch:<{arch_w}}  "
            f"{img.source:<{source_w}}  "
            f"{C[status_color]}{img.status:<{status_w}}{C['RST']}"
        )
    return lines


def _render_images(images: list[_ImageInfo]) -> None:
    _render_section("INSTALLED IMAGES")
    if not images:
        msg(f"  {C['YELLOW']}No containers are installed.{C['RST']}")
        msg()
        msg(f"  {C['CYAN']}Install one with: {C['GREEN']}{PROGRAM_NAME} install ubuntu:25.10{C['RST']}")
        return

    total_bytes = sum(i.size_bytes for i in images)
    msg(f"  {C['CYAN']}{len(images)} container(s), {fmt_size(total_bytes)} total{C['RST']}")
    msg()
    for line in _format_image_table(images):
        msg(line)

    detailed = [i for i in images if i.source_url or i.image_type]
    if detailed:
        msg()
        for img in detailed:
            msg(f"  {C['GREEN']}{img.name}{C['RST']}:")
            if img.source_url:
                msg(f"    {C['CYAN']}Source URL:{C['RST']} {img.source_url}")
            if img.image_type:
                msg(f"    {C['CYAN']}Image type:{C['RST']} {img.image_type}")


_CAP_GLYPH = {"ok": (_OK, "GREEN"), "warn": (_WARN, "YELLOW"), "bad": (_BAD, "RED"), "info": ("\u2022", "CYAN")}


def _render_capabilities(caps: list[_Capability]) -> None:
    _render_section("HOST CAPABILITIES")
    if not caps:
        msg(f"  {C['CYAN']}No capability checks available.{C['RST']}")
        return
    label_w = max(len(c.label) for c in caps) + 1
    for cap in caps:
        glyph, color = _CAP_GLYPH.get(cap.level, _CAP_GLYPH["info"])
        msg(
            f"  {C[color]}{glyph}{C['RST']} "
            f"{C['CYAN']}{cap.label + ':':<{label_w}}{C['RST']} "
            f"{C['WHITE']}{cap.value}{C['RST']}"
        )


def _render_kernel_config() -> None:
    """Show which CONFIG_* options chroot-distro relies on are enabled.

    Reads the kernel build config (``/proc/config.gz`` and friends) and lists
    each option grouped by the feature it powers. When the config can't be
    read (common on locked-down Android kernels) this is reported as a single
    informational line rather than a wall of 'unknown' rows.
    """
    _render_section("KERNEL CONFIG")
    path, text = find_kernel_config()
    parsed = parse_kernel_config(text) if text is not None else None

    if parsed is None:
        msg(
            f"  {C['YELLOW']}{_WARN}{C['RST']} "
            f"{C['WHITE']}Kernel config not readable "
            f"(no /proc/config.gz or /boot/config-*).{C['RST']}"
        )
        msg(
            f"    {C['CYAN']}Set CONFIG=/path/to/.config and re-run "
            f"'{PROGRAM_NAME} info' to check feature support.{C['RST']}"
        )
        return

    msg(f"  {C['CYAN']}Read from {path}{C['RST']}")
    missing_required: list[str] = []

    for group in KERNEL_FLAG_GROUPS:
        msg()
        msg(f"  {C['WHITE']}{group.title}{C['RST']}")
        # Width of the widest "CONFIG_NAME" label in this group for alignment.
        label_w = max(len("CONFIG_" + flag.name) for flag in group.flags) + 1
        for flag in group.flags:
            status = lookup_flag(parsed, flag.name)
            if status == CONFIG_BUILTIN:
                glyph, color, state = _OK, "GREEN", "enabled"
            elif status == CONFIG_MODULE:
                glyph, color, state = _OK, "GREEN", "enabled (module)"
            elif status == CONFIG_UNKNOWN:
                glyph, color, state = "\u2022", "CYAN", "unknown"
            else:
                # Missing: red when the option is required for isolation,
                # yellow when it only affects an optional extra.
                if flag.required:
                    glyph, color, state = _BAD, "RED", "missing (required)"
                    missing_required.append("CONFIG_" + flag.name)
                else:
                    glyph, color, state = _WARN, "YELLOW", "missing (optional)"
            label = "CONFIG_" + flag.name
            msg(
                f"    {C[color]}{glyph}{C['RST']} "
                f"{C['CYAN']}{label + ':':<{label_w}}{C['RST']} "
                f"{C['WHITE']}{state}{C['RST']} "
                f"{C['CYAN']}({flag.purpose}){C['RST']}"
            )

    msg()
    if missing_required:
        msg(
            f"  {C['RED']}{_BAD}{C['RST']} "
            f"{C['WHITE']}Namespace isolation (--isolated, CD_USE_NS=1) cannot "
            f"work fully without: {', '.join(missing_required)}.{C['RST']}"
        )
    else:
        msg(
            f"  {C['GREEN']}{_OK}{C['RST']} "
            f"{C['WHITE']}All kernel options required for namespace isolation "
            f"are present.{C['RST']}"
        )


def _running_summary(images: list[_ImageInfo]) -> int:
    """Return the number of containers with live processes or a namespace holder."""
    if not images:
        return 0
    try:
        from chroot_distro.commands.ps import _is_running
    except ImportError:
        return 0
    count = 0
    for img in images:
        try:
            if _is_running(img.name):
                count += 1
        except OSError:
            continue
    return count


def _render_analysis(images: list[_ImageInfo]) -> None:
    flagged = [i for i in images if i.findings]
    _render_section("ANALYSIS")
    if not images:
        msg(f"  {C['CYAN']}Nothing to analyze.{C['RST']}")
        return
    if not flagged:
        msg(f"  {C['GREEN']}No issues detected across {len(images)} container(s).{C['RST']}")
        return
    for img in flagged:
        msg(f"  {C['YELLOW']}{img.name}{C['RST']}:")
        for finding in img.findings:
            msg(f"    {C['RED']}\u2718{C['RST']} {C['WHITE']}{finding}{C['RST']}")


def command_info(args) -> None:
    """Print a structured diagnostics report for bug reports and support.

    Read-only: collects program, host (Linux distro or Termux/Android), and
    per-image facts plus lightweight analysis. Like ``list``/``ps`` it is
    rootless on Termux, but elevates on regular Linux so it inspects the same
    root-owned data directory where containers are installed.
    """
    host_arch = get_device_cpu_arch()
    host = _gather_host_info()
    images = _gather_images(host_arch)
    capabilities = _gather_capabilities(images, host_arch)
    running = _running_summary(images)

    _render_basic()
    _render_host(host, host_arch)
    _render_capabilities(capabilities)
    _render_kernel_config()
    _render_images(images)
    if images:
        msg()
        msg(f"  {C['CYAN']}Running now: {C['WHITE']}{running} of {len(images)} container(s){C['RST']}")
    _render_analysis(images)

    msg()
    msg(f"  {C['CYAN']}Report issues at https://github.com/sabamdarif/chroot-distro/issues{C['RST']}")
    msg()


__all__ = ("command_info",)
