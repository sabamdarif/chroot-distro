import struct
from unittest.mock import MagicMock, patch

from chroot_distro.arch import (
    Platform,
    _elf_arch,
    detect_installed_arch,
    get_device_cpu_arch,
    get_device_platform,
    needs_emulation,
    normalize_arch,
    parse_platform,
    platform_from_arch,
    supports_32bit,
)


def test_get_device_cpu_arch():
    # Test normalization of armv7l / armv8l
    with patch("os.uname") as mock_uname:
        mock_uname.return_value.machine = "armv7l"
        assert get_device_cpu_arch() == "arm"

        mock_uname.return_value.machine = "armv8l"
        assert get_device_cpu_arch() == "arm"

        mock_uname.return_value.machine = "x86_64"
        assert get_device_cpu_arch() == "x86_64"

        mock_uname.return_value.machine = "aarch64"
        assert get_device_cpu_arch() == "aarch64"


def test_supports_32bit():
    with patch("os.uname") as mock_uname:
        # x86_64 always supports 32-bit (i686)
        mock_uname.return_value.machine = "x86_64"
        assert supports_32bit() is True

        # aarch64 depends on personality syscall
        mock_uname.return_value.machine = "aarch64"
        with patch("ctypes.CDLL") as mock_cdll:
            mock_libc = MagicMock()
            mock_cdll.return_value = mock_libc

            # Case: personality returns valid original (e.g. 0)
            mock_libc.personality.return_value = 0
            assert supports_32bit() is True

            # Case: personality returns -1 (unsupported)
            mock_libc.personality.return_value = -1
            assert supports_32bit() is False


def test_normalize_arch():
    assert normalize_arch("aarch64") == "aarch64"
    assert normalize_arch("x86_64") == "x86_64"
    assert normalize_arch("arm") == "arm"
    assert normalize_arch("arm64") == "aarch64"
    assert normalize_arch("amd64") == "x86_64"
    assert normalize_arch("386") == "i686"
    assert normalize_arch("linux/arm64") == "aarch64"
    assert normalize_arch("linux/amd64") == "x86_64"
    assert normalize_arch("unknown") is None


def test_platform_parsing_and_round_trip():
    cases = {
        "linux/amd64": "x86_64",
        "linux/arm64": "aarch64",
        "linux/arm/v7": "arm",
        "linux/386": "i686",
        "linux/riscv64": "riscv64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
    }
    for value, arch in cases.items():
        platform = parse_platform(value)
        assert isinstance(platform, Platform)
        assert platform.to_arch() == arch
        assert parse_platform(platform.format()) == platform

    assert parse_platform("arm64").format() == "linux/arm64"
    assert parse_platform("arm").format() == "linux/arm/v7"
    assert parse_platform("linux/arm/v7").variant == "v7"
    assert platform_from_arch("arm").format() == "linux/arm/v7"


def test_platform_rejects_invalid_values():
    for value in ("", "linux", "linux/unknown", "windows/amd64", "linux/amd64/v2", "linux/arm/v6", "linux//amd64"):
        try:
            parse_platform(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {value!r}")


def test_get_device_platform(monkeypatch):
    monkeypatch.setattr("chroot_distro.arch.get_device_cpu_arch", lambda: "arm")
    assert get_device_platform() == Platform("linux", "arm", "v7")


def test_elf_arch(tmp_path):
    # Test non-existent file
    assert _elf_arch(str(tmp_path / "non_existent")) == ""

    # Test file too small
    small_file = tmp_path / "small"
    small_file.write_bytes(b"ELF")
    assert _elf_arch(str(small_file)) == ""

    # Test not an ELF binary
    not_elf = tmp_path / "not_elf"
    not_elf.write_bytes(b"12345678901234567890")
    assert _elf_arch(str(not_elf)) == ""

    # Test valid ELF headers (little endian EM_AARCH64)
    # Offset 18 is e_machine (2 bytes). 183 is EM_AARCH64.
    # ident[5] == 1 is EI_DATA LE
    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[5] = 1  # LE
    struct.pack_into("<H", header, 18, 183)

    elf_file = tmp_path / "elf_aarch64"
    elf_file.write_bytes(bytes(header))
    assert _elf_arch(str(elf_file)) == "aarch64"

    # Test valid ELF headers (big endian EM_X86_64)
    # 62 is EM_X86_64
    header_be = bytearray(20)
    header_be[:4] = b"\x7fELF"
    header_be[5] = 2  # BE
    struct.pack_into(">H", header_be, 18, 62)

    elf_file_be = tmp_path / "elf_x86_64"
    elf_file_be.write_bytes(bytes(header_be))
    assert _elf_arch(str(elf_file_be)) == "x86_64"


@patch("chroot_distro.paths.container_rootfs")
def test_detect_installed_arch(mock_container_rootfs, tmp_path):
    mock_container_rootfs.return_value = str(tmp_path)

    # Setup a dummy binary
    bin_dir = tmp_path / "usr" / "bin"
    bin_dir.mkdir(parents=True)
    bash_path = bin_dir / "bash"

    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[5] = 1  # LE
    struct.pack_into("<H", header, 18, 183)  # EM_AARCH64
    bash_path.write_bytes(bytes(header))

    # Test via container name
    assert detect_installed_arch("my_container") == "aarch64"

    # Test via absolute path
    assert detect_installed_arch(str(tmp_path)) == "aarch64"

    # Test unknown
    bash_path.unlink()
    assert detect_installed_arch("my_container") == "unknown"


def test_needs_emulation():
    assert needs_emulation("x86_64", "x86_64") is False
    assert needs_emulation("aarch64", "x86_64") is True

    with patch("chroot_distro.arch.supports_32bit", return_value=True):
        assert needs_emulation("i686", "x86_64") is False
        assert needs_emulation("arm", "aarch64") is False
        # A 64-bit CPU only runs the 32-bit half of its own family.
        assert needs_emulation("i686", "aarch64") is True

    with patch("chroot_distro.arch.supports_32bit", return_value=False):
        assert needs_emulation("arm", "aarch64") is True
