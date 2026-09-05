# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""CPU architecture: what the host is, what an image is, what a rootfs turned out to be.

Three naming schemes meet here. This program's own (`aarch64`, `arm`, `i686`,
`x86_64`, `riscv64`), `uname -m`'s (which spells 32-bit ARM `armv7l`, collapsed
along with `armv8l` to `arm` on the way in), and Docker's platform strings, which
`normalize_arch` accepts bare or `linux/`-prefixed and answers `None` for rather
than guessing.

`detect_installed_arch` reads the `e_machine` field out of the first shell or
busybox it finds in the rootfs, because that is ground truth: a container may
have arrived from a tarball with no manifest, or from a manifest naming a
platform the files do not match. `supports_32bit` asks the kernel through
`personality(PER_LINUX32)` and puts the previous value back, since on arm64
whether 32-bit userspace runs is a kernel build option and not something the
machine name says.

`needs_emulation` is the single place that answers whether a rootfs needs QEMU,
so a 32-bit guest on a 64-bit host of the same family asks `supports_32bit`
instead of counting as foreign. `ELF_MACHINE_BY_ARCH` is the machine table the
other way round, for the header `helpers/binfmt.py` registers a match on.
"""

import ctypes
import dataclasses
import os
import struct

from chroot_distro.constants import TERMUX_PREFIX


def get_device_cpu_arch() -> str:
    """Return the host CPU arch in chroot-distro's naming scheme.

    armv7l / armv8l are collapsed to "arm"; everything else is the
    raw `uname -m` value.
    """
    machine = os.uname().machine
    if machine in ("armv7l", "armv8l"):
        return "arm"
    return machine


def supports_32bit() -> bool:
    """Return True if the host CPU supports 32-bit userspace execution."""
    machine = os.uname().machine

    if machine in ("x86_64", "amd64"):
        return True

    if machine in ("aarch64", "arm64"):
        per_linux32 = 0x0008
        try:
            libc = ctypes.CDLL(None)
            prev = libc.personality(per_linux32)

            if prev == -1:
                return False
            libc.personality(prev)
            return True
        except Exception:
            return False

    return True


_ELF_MACHINE_MAP = {
    3: "i686",  # EM_386
    40: "arm",  # EM_ARM
    62: "x86_64",  # EM_X86_64
    183: "aarch64",  # EM_AARCH64
    243: "riscv64",  # EM_RISCV
}

ELF_MACHINE_BY_ARCH = {name: machine for machine, name in _ELF_MACHINE_MAP.items()}

# Host/guest pairs whose 32-bit userspace the 64-bit CPU runs without emulation.
_NATIVE_32BIT = frozenset({("x86_64", "i686"), ("aarch64", "arm")})


def needs_emulation(image_arch: str, host_arch: str = "") -> bool:
    """Return True if *image_arch* binaries cannot run on this CPU as they are."""
    host = host_arch or get_device_cpu_arch()
    if image_arch == host:
        return False
    if (host, image_arch) in _NATIVE_32BIT:
        return not supports_32bit()
    return True


def _elf_arch(path: str) -> str:
    """Return the arch name for an ELF binary, or '' on failure."""
    try:
        with open(path, "rb") as fh:
            ident = fh.read(20)
        if len(ident) < 20 or ident[:4] != b"\x7fELF":
            return ""
        fmt = "<H" if ident[5] == 1 else ">H"  # EI_DATA: 1=LE, 2=BE
        e_machine = struct.unpack_from(fmt, ident, 18)[0]
        return _ELF_MACHINE_MAP.get(e_machine, "")
    except OSError:
        return ""


def detect_installed_arch(container_name_or_rootfs: str) -> str:
    """Detect CPU architecture of an installed container by reading ELF headers.

    Accepts either a plain container name (resolved via paths.container_rootfs)
    or a full path to the rootfs directory.
    """
    if os.sep in container_name_or_rootfs or container_name_or_rootfs.startswith("/"):
        root = container_name_or_rootfs
    else:
        from chroot_distro.paths import container_rootfs

        root = container_rootfs(container_name_or_rootfs)

    candidates = [
        "/usr/bin/bash",
        "/usr/bin/sh",
        "/usr/bin/su",
        "/usr/bin/busybox",
        f"{TERMUX_PREFIX}/bin/bash",
        "/bin/bash",
        "/bin/sh",
        "/bin/su",
        "/bin/busybox",
    ]
    for rel in candidates:
        arch = _elf_arch(root + rel)
        if arch:
            return arch
    return "unknown"


_KNOWN_ARCHS = {"aarch64", "arm", "i686", "riscv64", "x86_64"}

# Docker platform strings and alternative names -> chroot-distro arch.
_DOCKER_TO_PROOT = {
    "arm64": "aarch64",
    "arm/v7": "arm",
    "arm": "arm",
    "386": "i686",
    "amd64": "x86_64",
    "riscv64": "riscv64",
}


def normalize_arch(arch: str) -> str | None:
    """Return a canonical chroot-distro arch name, or None if unrecognised.

    Accepts native names (aarch64, x86_64 ...), bare Docker names
    (arm64, amd64 ...), and linux/-prefixed Docker platform strings.
    """
    s = arch.strip()
    if s.startswith("linux/"):
        s = s[6:]
    if s in _KNOWN_ARCHS:
        return s
    return _DOCKER_TO_PROOT.get(s)


_SUPPORTED_PLATFORM_ARCHES = frozenset({"amd64", "arm64", "arm", "386", "riscv64"})


@dataclasses.dataclass(frozen=True)
class Platform:
    """A normalized OCI platform supported by chroot-distro."""

    os: str
    architecture: str
    variant: str = ""

    def __post_init__(self) -> None:
        os_name = self.os.strip().lower()
        architecture = self.architecture.strip().lower()
        variant = self.variant.strip().lower()
        if os_name != "linux":
            raise ValueError(f"unsupported platform OS '{self.os}'")
        if architecture not in _SUPPORTED_PLATFORM_ARCHES:
            raise ValueError(f"unsupported platform architecture '{self.architecture}'")
        if architecture != "arm" and variant:
            raise ValueError(f"platform variant is only supported for arm, not '{architecture}'")
        if architecture == "arm" and variant not in ("", "v7"):
            raise ValueError(f"unsupported arm platform variant '{self.variant}'")
        object.__setattr__(self, "os", os_name)
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "variant", variant)

    def format(self) -> str:
        """Return the canonical OCI platform string."""
        suffix = f"/{self.variant}" if self.variant else ""
        return f"{self.os}/{self.architecture}{suffix}"

    def __str__(self) -> str:
        return self.format()

    def to_arch(self) -> str:
        """Return the existing chroot-distro architecture name."""
        docker_name = f"{self.architecture}/{self.variant}" if self.variant else self.architecture
        if docker_name in _DOCKER_TO_PROOT:
            return _DOCKER_TO_PROOT[docker_name]
        from chroot_distro.helpers.docker.refs import ARCH_TO_DOCKER

        for arch, (name, variant) in ARCH_TO_DOCKER.items():
            if (name, variant) == (self.architecture, self.variant):
                return arch
        raise ValueError(f"unsupported platform '{self}'")


def platform_from_arch(arch: str) -> Platform:
    """Convert a chroot-distro architecture name to a Linux platform."""
    normalized = normalize_arch(arch)
    if normalized is None:
        raise ValueError(f"unknown architecture '{arch}'")
    from chroot_distro.helpers.docker.refs import ARCH_TO_DOCKER

    docker_arch, variant = ARCH_TO_DOCKER.get(normalized, (normalized, ""))
    return Platform("linux", docker_arch, variant)


def parse_platform(value: str) -> Platform:
    """Parse and normalize a supported OCI platform or architecture alias."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("platform cannot be empty")

    parts = value.strip().lower().split("/")
    if len(parts) == 1:
        return platform_from_arch(parts[0])
    if len(parts) not in (2, 3) or not all(parts):
        raise ValueError(f"malformed platform '{value}'")

    os_name, arch_value = parts[:2]
    normalized = normalize_arch(arch_value)
    if normalized is None:
        raise ValueError(f"unknown platform architecture '{arch_value}'")
    from chroot_distro.helpers.docker.refs import ARCH_TO_DOCKER

    docker_arch, default_variant = ARCH_TO_DOCKER.get(normalized, (normalized, ""))
    variant = parts[2] if len(parts) == 3 else default_variant
    return Platform(os_name, docker_arch, variant)


def get_device_platform() -> Platform:
    """Return the host CPU as a normalized Linux platform."""
    return platform_from_arch(get_device_cpu_arch())


# Machine string reported by `uname -m` for each arch.
