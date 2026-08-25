import pytest

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
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == (
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib/i386-linux-gnu/",
    )


def test_detect_guest_lib_dirs_lib64(tmp_path):
    (tmp_path / "usr/lib64").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib64/", "/usr/lib/")


def test_detect_guest_lib_dirs_fallback(tmp_path):
    (tmp_path / "usr/lib").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib/", "/usr/lib/")


def test_detect_guest_lib_dirs_lib32_override(tmp_path):
    (tmp_path / "usr/lib64").mkdir(parents=True)
    (tmp_path / "usr/lib32").mkdir(parents=True)
    assert nvidia._detect_guest_lib_dirs(str(tmp_path)) == ("/usr/lib64/", "/usr/lib32/")


# ── _host_lib_to_guest_path ───────────────────────────────────────────────────
def test_host_lib_remap_multiarch():
    lib64, lib32 = "/usr/lib64/", "/usr/lib32/"
    assert (
        nvidia._host_lib_to_guest_path("/usr/lib/x86_64-linux-gnu/libcuda.so", lib64, lib32) == "/usr/lib64/libcuda.so"
    )
    assert nvidia._host_lib_to_guest_path("/usr/lib/i386-linux-gnu/libcuda.so", lib64, lib32) == "/usr/lib32/libcuda.so"


def test_host_lib_remap_rpm():
    assert nvidia._host_lib_to_guest_path("/usr/lib64/libcuda.so", "/L64/", "/L32/") == "/L64/libcuda.so"
    assert nvidia._host_lib_to_guest_path("/usr/lib32/libcuda.so", "/L64/", "/L32/") == "/L32/libcuda.so"


def test_host_lib_remap_catchall_plain_usrlib():
    # Bare /usr/lib/ that matched none of the specific rules -> lib32 catch-all.
    assert nvidia._host_lib_to_guest_path("/usr/lib/libcuda.so", "/L64/", "/L32/") == "/L32/libcuda.so"


def test_host_lib_remap_unrelated_path_unchanged():
    assert nvidia._host_lib_to_guest_path("/opt/cuda/libcuda.so", "/L64/", "/L32/") == "/opt/cuda/libcuda.so"


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
