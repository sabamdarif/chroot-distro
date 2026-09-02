from unittest.mock import patch

import pytest

from chroot_distro.commands.login import bindings
from chroot_distro.helpers import nvidia


# ── _is_glvnd_neutral ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/usr/lib/libGLX_nvidia.so.0", False),  # vendor lib, not neutral
    ],
)
def test_is_glvnd_neutral_vendor(path, expected):
    assert nvidia._is_glvnd_neutral(path) is expected


def test_is_glvnd_neutral_matches_known_names():
    # Drive purely off the module's own table so we don't hardcode guesses.
    for name in nvidia._GLVND_NEUTRAL_BASENAMES:
        assert nvidia._is_glvnd_neutral(f"/usr/lib/{name}") is True
        assert nvidia._is_glvnd_neutral(f"/usr/lib/{name}.1") is True


# ── _detect_guest_lib_dirs ────────────────────────────────────────────────────
def test_detect_guest_lib_dirs_multiarch(tmp_path):
    (tmp_path / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
    (tmp_path / "usr/lib/i386-linux-gnu").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == (
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib/i386-linux-gnu/",
    )


def test_detect_guest_lib_dirs_multiarch_without_i386(tmp_path):
    # A pure 64-bit image: no 32-bit tree is invented for it.
    (tmp_path / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib/x86_64-linux-gnu/", None)


def test_detect_guest_lib_dirs_lib64(tmp_path):
    (tmp_path / "usr/lib64").mkdir(parents=True)
    (tmp_path / "usr/lib").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib64/", "/usr/lib/")


def test_detect_guest_lib_dirs_fallback(tmp_path):
    # Merged /usr/lib: the same directory cannot hold both word sizes.
    (tmp_path / "usr/lib").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib/", None)


def test_detect_guest_lib_dirs_lib32_override(tmp_path):
    (tmp_path / "usr/lib64").mkdir(parents=True)
    (tmp_path / "usr/lib32").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib64/", "/usr/lib32/")


# ── _is_elf64 ─────────────────────────────────────────────────────────────────
def test_is_elf64_reads_ei_class(tmp_path):
    elf64 = tmp_path / "lib64.so"
    elf64.write_bytes(b"\x7fELF\x02\x01\x01")
    elf32 = tmp_path / "lib32.so"
    elf32.write_bytes(b"\x7fELF\x01\x01\x01")
    assert nvidia._is_elf64(str(elf64)) is True
    assert nvidia._is_elf64(str(elf32)) is False


def test_is_elf64_non_elf_or_missing_counts_as_64(tmp_path):
    script = tmp_path / "libc.so"
    script.write_text("GROUP ( libc.so.6 )")
    assert nvidia._is_elf64(str(script)) is True
    assert nvidia._is_elf64(str(tmp_path / "gone.so")) is True


# ── _host_lib_to_guest_path ───────────────────────────────────────────────────
def test_host_lib_remap_multiarch(monkeypatch):
    monkeypatch.setattr(nvidia, "_is_elf64", lambda path: "i386" not in path)
    lib64, lib32 = "/usr/lib64/", "/usr/lib32/"
    assert (
        nvidia._host_lib_to_guest_path("/usr/lib/x86_64-linux-gnu/libcuda.so", lib64, lib32) == "/usr/lib64/libcuda.so"
    )
    assert nvidia._host_lib_to_guest_path("/usr/lib/i386-linux-gnu/libcuda.so", lib64, lib32) == "/usr/lib32/libcuda.so"


def test_host_lib_remap_rpm():
    assert nvidia._host_lib_to_guest_path("/usr/lib64/libcuda.so", "/L64/", "/L32/") == "/L64/libcuda.so"


def test_host_lib_remap_merged_usr_lib_follows_elf_class(monkeypatch):
    # Arch-family host: 64-bit objects in /usr/lib, 32-bit in /usr/lib32, so the
    # directory name is no guide and the ELF class decides.
    monkeypatch.setattr(nvidia, "_is_elf64", lambda path: "/usr/lib32/" not in path)
    assert nvidia._host_lib_to_guest_path("/usr/lib/libGLX_nvidia.so.0", "/L64/", "/L32/") == "/L64/libGLX_nvidia.so.0"
    assert (
        nvidia._host_lib_to_guest_path("/usr/lib32/libGLX_nvidia.so.0", "/L64/", "/L32/") == "/L32/libGLX_nvidia.so.0"
    )


def test_host_lib_remap_keeps_subdirectory(monkeypatch):
    monkeypatch.setattr(nvidia, "_is_elf64", lambda path: True)
    assert (
        nvidia._host_lib_to_guest_path("/usr/lib/vdpau/libvdpau_nvidia.so.1", "/L64/", "/L32/")
        == "/L64/vdpau/libvdpau_nvidia.so.1"
    )


def test_host_lib_remap_dropped_without_guest_lib32(monkeypatch):
    monkeypatch.setattr(nvidia, "_is_elf64", lambda path: False)
    assert nvidia._host_lib_to_guest_path("/usr/lib32/libcuda.so", "/L64/", None) is None


def test_host_lib_remap_unrelated_path_unchanged(monkeypatch):
    monkeypatch.setattr(nvidia, "_is_elf64", lambda path: True)
    assert nvidia._host_lib_to_guest_path("/opt/cuda/libcuda.so", "/L64/", "/L32/") == "/opt/cuda/libcuda.so"


# ── _guest_ships_library ──────────────────────────────────────────────────────
def test_guest_ships_library_ignores_leftover_bind_stub(tmp_path):
    stub = tmp_path / "libGLX_nvidia.so.610"
    stub.write_bytes(b"")
    soname_link = tmp_path / "libGLX_nvidia.so.0"
    soname_link.symlink_to(stub)
    dangling = tmp_path / "libEGL_nvidia.so.0"
    dangling.symlink_to(tmp_path / "gone.so")
    real = tmp_path / "libcuda.so.1"
    real.write_bytes(b"\x7fELF\x02")

    # An empty file and a symlink into one are this program's own bind targets,
    # left behind by an earlier session's unmount.
    assert nvidia._guest_ships_library(str(stub)) is False
    assert nvidia._guest_ships_library(str(soname_link)) is False
    assert nvidia._guest_ships_library(str(dangling)) is False
    assert nvidia._guest_ships_library(str(tmp_path / "absent.so")) is False
    assert nvidia._guest_ships_library(str(real)) is True


# ── get_bindings: one host library, several guest names ───────────────────────
def test_get_bindings_keeps_every_guest_name_of_one_source():
    source = "/usr/lib/libGLX_nvidia.so.610.57.04"
    pairs = [
        (source, "/usr/lib/x86_64-linux-gnu/libGLX_nvidia.so"),
        (source, "/usr/lib/x86_64-linux-gnu/libGLX_nvidia.so.0"),
        (source, "/usr/lib/x86_64-linux-gnu/libGLX_nvidia.so.610.57.04"),
    ]
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
        patch.object(bindings.nvidia_helper, "get_nvidia_integration", return_value=(pairs, {})),
    ):
        binds, _rslave = bindings.get_bindings(rootfs="/fake/rootfs", nvidia_integration=True)

    # The soname a loader opens (libGLX_nvidia.so.0) is one of three names for
    # the same host file, so none of them may be dropped as a duplicate.
    dsts = [dst for src, dst in binds if src == source]
    assert dsts == ["/fake/rootfs" + guest for _s, guest in pairs]


# ── nvidia_env_vars (branches on is_wsl) ──────────────────────────────────────
def test_nvidia_env_vars_wsl(monkeypatch):
    monkeypatch.setattr(nvidia, "is_wsl", lambda: True)
    env = nvidia.nvidia_env_vars()
    assert env["GALLIUM_DRIVER"] == "d3d12"
    assert "__NV_PRIME_RENDER_OFFLOAD" not in env


def test_nvidia_env_vars_native(monkeypatch):
    monkeypatch.setattr(nvidia, "is_wsl", lambda: False)
    env = nvidia.nvidia_env_vars()
    assert env["__NV_PRIME_RENDER_OFFLOAD"] == "1"
    assert env["__GLX_VENDOR_LIBRARY_NAME"] == "nvidia"
    assert "GALLIUM_DRIVER" not in env


# ── is_wsl (reads /proc/version) ──────────────────────────────────────────────
def test_is_wsl_true(monkeypatch, tmp_path):
    ver = tmp_path / "version"
    ver.write_text("Linux version 5.15 microsoft-standard-WSL2")
    import builtins

    real_open = builtins.open

    def fake_open(path, *a, **k):
        if path == "/proc/version":
            return real_open(str(ver), *a, **k)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert nvidia.is_wsl() is True


def test_is_wsl_missing_proc(monkeypatch):
    import builtins

    def boom(path, *a, **k):
        if path == "/proc/version":
            raise OSError("nope")
        return builtins.open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", boom)
    assert nvidia.is_wsl() is False
