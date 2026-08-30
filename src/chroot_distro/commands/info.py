# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro info`: one report a bug can be filed with, and nothing changed.

Read-only from end to end: every value is read, probed or computed, never
written. The command elevates when root is available, since `/proc/config.gz` and
the data directories are root-owned, and stays useful without it by falling back
to the runtime probes in `commands/kernel_config.py`.

This is the file where `shutil.which` is a capability report rather than a call:
`_detect_escalation_tool` says which of sudo, doas, pkexec or su exists so the
Privileges line can name it, and nothing here execs what it finds. The isolation
tier comes from `namespace.probe_and_report_namespaces`, the same probe `login`
uses, so the report and the real run cannot disagree.

The per-image findings are the point of the analysis section: an empty rootfs, a
missing `manifest.json` (which is what makes `reset`, `diff` and `run`
unavailable), or an arch that needs emulation, which is then cross-checked
against whether a QEMU binfmt handler is actually registered.
`_has_rootfs_structure` stays lenient on purpose, since a distroless image
legitimately ships no `/etc`, and a directory left over from an interrupted
install is not listed as an image at all.
"""

import ctypes
import json
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field

from chroot_distro.arch import detect_installed_arch, get_device_cpu_arch, needs_emulation, supports_32bit
from chroot_distro.commands.kernel_config import (
    CONFIG_BUILTIN,
    CONFIG_MODULE,
    CONFIG_UNKNOWN,
    KERNEL_FLAG_GROUPS,
    PROBE_ABSENT,
    PROBE_PRESENT,
    find_kernel_config,
    lookup_flag,
    parse_kernel_config,
    probe_devpts_multi_instance,
    probe_flag_runtime,
)
from chroot_distro.commands.list_cmd import (
    _ensure_manifest_readable,
    _iter_container_names,
    _read_image_source,
    _rootfs_size_bytes,
)
from chroot_distro.constants import (
    BASE_CACHE_DIR,
    CANONICAL_PROGRAM_NAME,
    IS_TERMUX,
    LAYER_CACHE_DIR,
    PROGRAM_NAME,
    PROGRAM_VERSION,
    RUNTIME_DIR,
    TERMUX_APP_PACKAGE,
)
from chroot_distro.helpers.binfmt import BINFMT_DIR, covered_arches
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
    """One host capability check result for the report."""

    label: str
    value: str
    level: str = "info"  # "ok", "warn", "bad" or "info": picks glyph and color


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


def _system_property(key: str) -> str:
    """Read one Android system property, or "" when it cannot be read.

    The property is asked of libc, the way getprop(1) itself asks: the values
    live in a shared memory area no file exposes, and __system_property_get
    writes into a caller-supplied buffer of PROP_VALUE_MAX (92) bytes.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        getter = libc.__system_property_get
    except (OSError, AttributeError):
        return ""
    getter.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    getter.restype = ctypes.c_int
    buf = ctypes.create_string_buffer(92)
    if getter(key.encode(), buf) <= 0:
        return ""
    return buf.value.decode(errors="replace").strip()


def _read_build_prop(keys: tuple[str, ...]) -> dict[str, str]:
    """Read selected Android system properties, falling back to build.prop."""
    found: dict[str, str] = {}
    for key in keys:
        value = _system_property(key)
        if value:
            found[key] = value
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

    try:
        kernel = os.uname().release
    except (OSError, AttributeError):
        kernel = platform.release()
    fields.append(("Kernel", kernel or _NA))
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

    try:
        kernel = os.uname().release
    except (OSError, AttributeError):
        kernel = platform.release()
    fields.append(("Kernel", kernel or _NA))
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
    if not os.path.isdir(BINFMT_DIR):
        value = "binfmt_misc not mounted"
        return value, ("bad" if needs_emulation else "info")
    covered = covered_arches()
    if covered:
        return f"binfmt_misc + qemu ({', '.join(covered)})", "ok"
    value = "binfmt_misc mounted, no emulator registered"
    return value, ("bad" if needs_emulation else "info")


def _userns_enabled() -> bool | None:
    """Return True/False if user-namespace support is known, else None."""
    path = "/proc/sys/user/max_user_namespaces"
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip()) > 0
    except (OSError, ValueError):
        probe = probe_flag_runtime("USER_NS")
        if probe == PROBE_PRESENT:
            return True
        if probe == PROBE_ABSENT:
            return False
        return None


def _namespace_status() -> tuple[str, str]:
    """Return (value, level) describing kernel namespace + userns support.

    Isolation is unshare(2) and setns(2) from this process, so there is no tool
    to look for: what decides it is the kernel.  /proc/self/ns answers that
    without root, which `info` may well be running without.
    """
    if probe_flag_runtime("NAMESPACES") == PROBE_ABSENT:
        return "not supported by this kernel (--isolated unavailable)", "warn"
    userns = _userns_enabled()
    if userns is False:
        return "supported, user namespaces disabled", "warn"
    if userns is None:
        return "supported", "ok"
    return "supported, user namespaces enabled", "ok"


def _read_sysctl_int(path: str) -> int | None:
    """Return the integer value of a sysctl file, or None if unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _userns_knob_caps() -> list["_Capability"]:
    """Report the runtime knobs that gate CLONE_NEWUSER (user namespaces)."""
    caps: list[_Capability] = []
    max_userns = _read_sysctl_int("/proc/sys/user/max_user_namespaces")
    if max_userns is not None:
        if max_userns == 0:
            caps.append(_Capability("max_user_namespaces", "0 (user namespaces disabled)", "warn"))
        else:
            caps.append(_Capability("max_user_namespaces", str(max_userns), "ok"))
    # Present mainly on Debian/Ubuntu/Arch-hardened kernels; absent elsewhere.
    unpriv = _read_sysctl_int("/proc/sys/kernel/unprivileged_userns_clone")
    if unpriv is not None:
        if unpriv == 1:
            caps.append(_Capability("unprivileged_userns_clone", "1 (rootless userns allowed)", "ok"))
        else:
            caps.append(
                _Capability("unprivileged_userns_clone", "0 (rootless userns blocked; root still works)", "info")
            )
    return caps


def _isolation_tier_status() -> tuple[str, str] | None:
    """Return (value, level) for the --isolated tier, using the same probe
    as ``login`` so the report and the real run agree."""
    try:
        from chroot_distro.helpers import namespace

        result = namespace.probe_and_report_namespaces()
    except Exception:
        return None
    if result.missing_mandatory:
        return "unavailable (no mount namespace on this kernel)", "warn"
    descriptions = {
        "B": "B: full user-namespace remap (container uids remapped, capabilities scoped)",
        "A": "A: user namespace active (capabilities scoped; uids not remapped)",
        "C": "C: capability-drop only (no user namespace; container root == host root)",
    }
    levels = {"B": "ok", "A": "ok", "C": "warn"}
    tier = result.isolation_tier
    value = descriptions.get(tier, tier)
    if tier == "A" and result.idmapped_mounts:
        value += "; idmapped mounts available (uid-remap not yet enabled)"
    elif tier != "C" and not result.idmapped_mounts:
        value += "; idmapped mounts unavailable"
    if not result.userns_mounts_ok:
        value += "; userns present but mounts rejected inside it"
    return value, levels.get(tier, "info")


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


def _dir_size_bytes(path: str, seen_files: set[str] | None = None) -> int:
    """Return total file size under *path*, ignoring unreadable entries."""
    if seen_files is None:
        seen_files = set()
    total = 0
    for dirpath, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            fpath = os.path.join(dirpath, name)
            try:
                real_fpath = os.path.realpath(fpath)
                if real_fpath in seen_files:
                    continue
                seen_files.add(real_fpath)
                total += os.path.getsize(fpath)
            except OSError:
                continue
    return total


def _cache_size() -> tuple[str, str]:
    """Return (value, level) describing the download cache size (excluding layers)."""
    seen_files: set[str] = set()
    _dir_size_bytes(LAYER_CACHE_DIR, seen_files)
    total = _dir_size_bytes(BASE_CACHE_DIR, seen_files)
    if total == 0:
        return "empty", "info"
    return f"{fmt_size(total)} (clear with '{PROGRAM_NAME} clear-cache')", "info"


def _layer_cache_size() -> tuple[str, str]:
    """Return (value, level) describing the OCI layer cache size."""
    total = _dir_size_bytes(LAYER_CACHE_DIR)
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

    from chroot_distro.elevate import is_root_available

    is_root = os.getuid() == 0
    if is_root:
        caps.append(_Capability("Privileges", "running as root", "ok"))
    elif is_root_available():
        tool = _detect_escalation_tool()
        if IS_TERMUX:
            caps.append(_Capability("Privileges", "not root, root is available (can elevate via su)", "info"))
        elif tool:
            caps.append(_Capability("Privileges", f"not root, can elevate via {tool}", "info"))
        else:
            caps.append(_Capability("Privileges", "not root, can elevate via daemon socket", "info"))
    else:
        if IS_TERMUX:
            caps.append(_Capability("Privileges", "not root, root is not available (su not found)", "bad"))
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

    # User-namespace readiness knobs + the isolation tier --isolated will use.
    caps.extend(_userns_knob_caps())
    tier_status = _isolation_tier_status()
    if tier_status is not None:
        caps.append(_Capability("Isolation tier", tier_status[0], tier_status[1]))

    if not IS_TERMUX:
        lsm = _lsm_status()
        if lsm:
            caps.append(_Capability("Security module", lsm[0], lsm[1]))

    disk_value, disk_level = _free_disk(RUNTIME_DIR)
    caps.append(_Capability("Disk (data dir)", disk_value, disk_level))

    cache_value, cache_level = _cache_size()
    caps.append(_Capability("Download cache", cache_value, cache_level))

    layer_value, layer_level = _layer_cache_size()
    caps.append(_Capability("OCI layer cache", layer_value, layer_level))

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
        # Flag only when no ELF binary AND no common top-level dir was found;
        # minimal/distroless images legitimately lack /etc files.
        info.findings.append("no recognizable rootfs layout (install may be incomplete)")

    if info.arch not in (_NA, "") and host_arch not in (_NA, "") and needs_emulation(info.arch, host_arch):
        info.findings.append(f"arch '{info.arch}' differs from host '{host_arch}' (needs emulation)")


def _gather_images(host_arch: str) -> list[_ImageInfo]:
    # Leftovers from interrupted installs carry no usable image data;
    # only report actually installed containers.
    names, _incomplete = _iter_container_names()
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
    label_w = 18
    _render_section(f"{CANONICAL_PROGRAM_NAME}")
    msg(_kv("Program", PROGRAM_NAME, label_w))
    msg(_kv("Version", PROGRAM_VERSION, label_w))
    msg(_kv("Python", platform.python_version(), label_w))

    exe_path = shutil.which("chroot-distro")
    if not exe_path and sys.argv and os.path.exists(sys.argv[0]):
        exe_path = os.path.abspath(sys.argv[0])
    if not exe_path:
        exe_path = "unknown"
    msg(_kv("Executable", exe_path, label_w))

    module_dir = "unknown"
    try:
        import chroot_distro

        if chroot_distro.__file__:
            module_dir = os.path.dirname(os.path.dirname(os.path.abspath(chroot_distro.__file__)))
    except Exception:
        pass
    msg(_kv("Module path", module_dir, label_w))

    msg(_kv("Data location", RUNTIME_DIR, label_w))
    msg(_kv("Cache location", BASE_CACHE_DIR, label_w))
    msg(_kv("OCI layer cache", LAYER_CACHE_DIR, label_w))


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


def _flag_status(flag, parsed: dict | None) -> tuple[str, str, str, bool]:
    """Resolve one kernel flag to (glyph, color, state_text, counts_as_missing).

    Uses the static kernel config when readable, else a live runtime probe.
    *counts_as_missing* is True only for required + confirmed-absent options.
    """
    # DEVPTS_MULTIPLE_INSTANCES: absent from configs >= 4.9 (always-on since
    # 4.7) and vendor configs have been seen lying about it, so the runtime
    # probe outranks the static config. Falls through on PROBE_UNKNOWN.
    if flag.name == "DEVPTS_MULTIPLE_INSTANCES":
        probe = probe_devpts_multi_instance()
        if probe == PROBE_PRESENT:
            return _OK, "GREEN", "per-mount instances", False
        if probe == PROBE_ABSENT:
            return _WARN, "YELLOW", "single shared instance (host /dev/pts is reused)", False

    if parsed is not None:
        status = lookup_flag(parsed, flag.name)
        if status in (CONFIG_BUILTIN, CONFIG_MODULE):
            state = "enabled" if status == CONFIG_BUILTIN else "enabled (module)"
            return _OK, "GREEN", state, False
        if status == CONFIG_UNKNOWN:
            return "\u2022", "CYAN", "unknown", False
        # Confirmed missing in a readable config.
        if flag.required:
            return _BAD, "RED", "missing (required)", True
        return _WARN, "YELLOW", "missing (optional)", False

    # No static config: probe the live kernel.
    probe = probe_flag_runtime(flag.name)
    if probe == PROBE_PRESENT:
        return _OK, "GREEN", "available (runtime)", False
    if probe == PROBE_ABSENT:
        if flag.required:
            return _BAD, "RED", "unavailable (required)", True
        return _WARN, "YELLOW", "unavailable (optional)", False
    return "\u2022", "CYAN", "unknown", False


def _render_kernel_config() -> None:
    """Show which CONFIG_* options chroot-distro relies on are enabled.

    Prefers the static kernel build config; falls back to probing the
    running kernel when it isn't readable (common on Android).
    """
    _render_section("KERNEL CONFIG")
    path, text = find_kernel_config()
    parsed = parse_kernel_config(text) if text is not None else None

    if parsed is not None:
        msg(f"  {C['CYAN']}Read from {path}{C['RST']}")
    else:
        if IS_TERMUX:
            msg(
                f"  {C['CYAN']}Kernel config not readable (requires root). "
                f"Probing the running kernel instead. For a definitive report, "
                f"provide a config file via 'CONFIG=/path/to/.config {PROGRAM_NAME} info'.{C['RST']}"
            )
        else:
            msg(
                f"  {C['CYAN']}Kernel config not readable; probing the running "
                f"kernel instead. For a definitive report run "
                f"'CONFIG=/path/to/.config {PROGRAM_NAME} info' or as root.{C['RST']}"
            )

    missing_required: list[str] = []
    for group in KERNEL_FLAG_GROUPS:
        if IS_TERMUX and group.title == "Cgroups":
            continue
        msg()
        msg(f"  {C['WHITE']}{group.title}{C['RST']}")
        label_w = max(len("CONFIG_" + flag.name) for flag in group.flags) + 1
        for flag in group.flags:
            glyph, color, state, counts_missing = _flag_status(flag, parsed)
            if counts_missing:
                missing_required.append("CONFIG_" + flag.name)
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
    return sum(1 for img in images if img.status != "idle")


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

    Read-only. Elevates to root when available (to read /proc/config.gz and
    root-owned data dirs); otherwise falls back to runtime probing.
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
