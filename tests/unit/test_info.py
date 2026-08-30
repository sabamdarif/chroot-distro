from unittest.mock import MagicMock, mock_open, patch

import chroot_distro.commands.info as info


def test_read_os_release_parses_quoted_values(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('PRETTY_NAME="Ubuntu 25.10"\nVERSION_ID="25.10"\n# comment\nNAME=Ubuntu\n')
    real_open = open
    # Redirect the candidate os-release paths to our temp file.
    with patch("builtins.open", side_effect=lambda *a, **k: real_open(f, *a[1:], **k)):
        data = info._read_os_release()
    assert data["PRETTY_NAME"] == "Ubuntu 25.10"
    assert data["VERSION_ID"] == "25.10"
    assert data["NAME"] == "Ubuntu"


def test_linux_host_info_uses_pretty_name():
    with patch.object(
        info,
        "_read_os_release",
        return_value={"PRETTY_NAME": "Debian GNU/Linux 13", "VERSION_ID": "13"},
    ):
        host = info._linux_host_info()
    assert host.kind == "Linux"
    field_dict = dict(host.fields)
    assert field_dict["Distribution"] == "Debian GNU/Linux 13"
    assert field_dict["Version"] == "13"


def test_termux_host_info_reports_android_version(monkeypatch):
    monkeypatch.setenv("TERMUX_VERSION", "0.118.1")
    props = {
        "ro.build.version.release": "14",
        "ro.build.version.sdk": "34",
        "ro.product.manufacturer": "Google",
        "ro.product.model": "Pixel 8",
        "ro.product.device": "shiba",
    }
    with patch.object(info, "_read_build_prop", return_value=props):
        host = info._termux_host_info()
    field_dict = dict(host.fields)
    assert host.kind == "Termux / Android"
    assert field_dict["Termux version"] == "0.118.1"
    assert field_dict["Android version"] == "14 (API 34)"
    assert "Google Pixel 8" in field_dict["Device"]


def test_analyze_image_flags_arch_mismatch():
    img = info._ImageInfo(name="alpine", size_bytes=1024, arch="x86_64")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert any("differs from host" in f for f in img.findings)


def test_analyze_image_flags_empty_rootfs():
    img = info._ImageInfo(name="broken", size_bytes=0, arch="aarch64")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert any("rootfs is empty" in f for f in img.findings)


def test_analyze_image_does_not_flag_minimal_rootfs():
    # Distroless/termux-docker style: arch detected, but no /etc files.
    img = info._ImageInfo(name="termux-docker", size_bytes=4096, arch="aarch64")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert not any("rootfs" in f for f in img.findings)


def test_analyze_image_flags_unrecognizable_rootfs():
    # No arch detected and no rootfs structure at all -> flagged.
    img = info._ImageInfo(name="junk", size_bytes=4096, arch=info._NA)
    with (
        patch("os.path.isfile", return_value=True),
        patch("os.path.isdir", return_value=False),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="aarch64")
    assert any("no recognizable rootfs layout" in f for f in img.findings)


def test_analyze_image_no_arch_flag_for_compatible_32bit():
    img = info._ImageInfo(name="i386", size_bytes=2048, arch="i686")
    with (
        patch("os.path.isfile", return_value=True),
        patch("chroot_distro.commands.info.container_manifest", return_value="/x/manifest.json"),
        patch("chroot_distro.commands.info.container_rootfs", return_value="/x/rootfs"),
    ):
        info._analyze_image(img, host_arch="x86_64")
    assert not any("differs from host" in f for f in img.findings)


def test_command_info_runs_without_containers():
    with (
        patch.object(info, "_iter_container_names", return_value=([], [])),
        patch.object(info, "get_device_cpu_arch", return_value="aarch64"),
        patch.object(info, "_gather_host_info", return_value=info._HostInfo("Linux", [("Kernel", "6.0")])),
        patch.object(info, "supports_32bit", return_value=True),
        patch.object(info, "_gather_capabilities", return_value=[]),
        patch.object(info, "msg") as mock_msg,
    ):
        info.command_info(MagicMock())
    # Report rendered something to stderr via msg().
    assert mock_msg.called
    rendered = " ".join(str(c.args[0]) for c in mock_msg.call_args_list if c.args)
    assert "No containers are installed." in rendered


def test_detect_escalation_tool_prefers_sudo():
    with patch("shutil.which", side_effect=lambda t: "/usr/bin/sudo" if t == "sudo" else None):
        assert info._detect_escalation_tool() == "sudo"
    with patch("shutil.which", return_value=None):
        assert info._detect_escalation_tool() == ""


def test_binfmt_qemu_status_flags_missing_handler_when_emulation_needed():
    with (
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.info.covered_arches", return_value=[]),
    ):
        value, level = info._binfmt_qemu_status(needs_emulation=True)
    assert level == "bad"
    assert "no emulator" in value


def test_binfmt_qemu_status_ok_with_handler():
    with (
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.info.covered_arches", return_value=["aarch64", "arm"]),
    ):
        value, level = info._binfmt_qemu_status(needs_emulation=True)
    assert level == "ok"
    assert "aarch64" in value and "arm" in value


def test_namespace_status_warns_when_the_kernel_lacks_namespaces():
    with patch.object(info, "probe_flag_runtime", return_value=info.PROBE_ABSENT):
        value, level = info._namespace_status()
    assert level == "warn"
    assert "--isolated" in value


def test_namespace_status_reports_userns_separately():
    with (
        patch.object(info, "probe_flag_runtime", return_value=info.PROBE_PRESENT),
        patch.object(info, "_userns_enabled", return_value=False),
    ):
        value, level = info._namespace_status()
    assert level == "warn"
    assert "user namespaces disabled" in value


def test_data_mount_flags_warns_on_nosuid():
    with patch("chroot_distro.helpers.android._read_data_mount", return_value=("/dev/x", "/data", "rw,nosuid,noexec")):
        value, level = info._data_mount_flags()
    assert level == "warn"
    assert "nosuid" in value and "noexec" in value


def test_gather_capabilities_reports_no_escalation_tool():
    with (
        patch("os.getuid", return_value=1000),
        patch("chroot_distro.elevate.is_root_available", return_value=False),
        patch.object(info, "_detect_escalation_tool", return_value=""),
        patch.object(info, "IS_TERMUX", False),
        patch.object(info, "_binfmt_qemu_status", return_value=("binfmt_misc + qemu", "ok")),
        patch.object(info, "_namespace_status", return_value=("unshare present", "ok")),
        patch.object(info, "_lsm_status", return_value=None),
        patch.object(info, "_free_disk", return_value=("10 GiB free", "info")),
        patch.object(info, "_cache_size", return_value=("empty", "info")),
        patch.object(info, "_layer_cache_size", return_value=("empty", "info")),
    ):
        caps = info._gather_capabilities(images=[], host_arch="x86_64")
    priv = next(c for c in caps if c.label == "Privileges")
    assert priv.level == "bad"
    assert "no sudo" in priv.value


def test_render_basic_outputs_new_fields():
    with patch.object(info, "msg") as mock_msg:
        info._render_basic()
    assert mock_msg.called
    rendered = " ".join(str(c.args[0]) for c in mock_msg.call_args_list if c.args)
    assert "Executable" in rendered
    assert "Module path" in rendered
    assert "Cache location" in rendered
    assert "OCI layer cache" in rendered


def test_userns_enabled_states():
    # Case 1: max_user_namespaces exists and is > 0
    mock_file = mock_open(read_data="1\n").return_value
    real_open = open

    def fake_open_present(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            return mock_file
        return real_open(path, *a, **k)

    with patch("builtins.open", side_effect=fake_open_present):
        assert info._userns_enabled() is True

    # Case 2: max_user_namespaces exists and is 0
    mock_file_zero = mock_open(read_data="0\n").return_value

    def fake_open_absent(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            return mock_file_zero
        return real_open(path, *a, **k)

    with patch("builtins.open", side_effect=fake_open_absent):
        assert info._userns_enabled() is False

    # Case 3: max_user_namespaces is missing/unreadable, but probe says present
    def fake_open_error(path, *a, **k):
        if path == "/proc/sys/user/max_user_namespaces":
            raise OSError
        return real_open(path, *a, **k)

    with (
        patch("builtins.open", side_effect=fake_open_error),
        patch.object(info, "probe_flag_runtime", return_value="present"),
    ):
        assert info._userns_enabled() is True

    # Case 4: max_user_namespaces is missing/unreadable, and probe says absent
    with (
        patch("builtins.open", side_effect=fake_open_error),
        patch.object(info, "probe_flag_runtime", return_value="absent"),
    ):
        assert info._userns_enabled() is False

    # Case 5: max_user_namespaces is missing/unreadable, and probe says unknown
    with (
        patch("builtins.open", side_effect=fake_open_error),
        patch.object(info, "probe_flag_runtime", return_value="unknown"),
    ):
        assert info._userns_enabled() is None


def test_gather_capabilities_privilege_states():
    # 1. Running as root
    with (
        patch("os.getuid", return_value=0),
        patch("chroot_distro.commands.info.IS_TERMUX", False),
        patch("chroot_distro.commands.info._binfmt_qemu_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._namespace_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._lsm_status", return_value=None),
        patch("chroot_distro.commands.info._free_disk", return_value=("", "info")),
        patch("chroot_distro.commands.info._cache_size", return_value=("", "info")),
        patch("chroot_distro.commands.info._layer_cache_size", return_value=("", "info")),
    ):
        caps = info._gather_capabilities(images=[], host_arch="x86_64")
        priv = next(c for c in caps if c.label == "Privileges")
        assert priv.level == "ok"
        assert "running as root" in priv.value

    # 2. Termux, not root, but root is available
    with (
        patch("os.getuid", return_value=1000),
        patch("chroot_distro.commands.info.IS_TERMUX", True),
        patch("chroot_distro.elevate.is_root_available", return_value=True),
        patch("chroot_distro.commands.info._data_mount_flags", return_value=("", "info")),
        patch("chroot_distro.commands.info._binfmt_qemu_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._namespace_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._free_disk", return_value=("", "info")),
        patch("chroot_distro.commands.info._cache_size", return_value=("", "info")),
        patch("chroot_distro.commands.info._layer_cache_size", return_value=("", "info")),
    ):
        caps = info._gather_capabilities(images=[], host_arch="aarch64")
        priv = next(c for c in caps if c.label == "Privileges")
        assert priv.level == "info"
        assert "root is available (can elevate via su)" in priv.value

    # 3. Termux, not root, root is not available
    with (
        patch("os.getuid", return_value=1000),
        patch("chroot_distro.commands.info.IS_TERMUX", True),
        patch("chroot_distro.elevate.is_root_available", return_value=False),
        patch("chroot_distro.commands.info._data_mount_flags", return_value=("", "info")),
        patch("chroot_distro.commands.info._binfmt_qemu_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._namespace_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._free_disk", return_value=("", "info")),
        patch("chroot_distro.commands.info._cache_size", return_value=("", "info")),
        patch("chroot_distro.commands.info._layer_cache_size", return_value=("", "info")),
    ):
        caps = info._gather_capabilities(images=[], host_arch="aarch64")
        priv = next(c for c in caps if c.label == "Privileges")
        assert priv.level == "bad"
        assert "root is not available (su not found)" in priv.value

    # 4. Linux, not root, can elevate via daemon
    with (
        patch("os.getuid", return_value=1000),
        patch("chroot_distro.commands.info.IS_TERMUX", False),
        patch("chroot_distro.elevate.is_root_available", return_value=True),
        patch("chroot_distro.commands.info._detect_escalation_tool", return_value=""),
        patch("chroot_distro.commands.info._binfmt_qemu_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._namespace_status", return_value=("", "info")),
        patch("chroot_distro.commands.info._lsm_status", return_value=None),
        patch("chroot_distro.commands.info._free_disk", return_value=("", "info")),
        patch("chroot_distro.commands.info._cache_size", return_value=("", "info")),
        patch("chroot_distro.commands.info._layer_cache_size", return_value=("", "info")),
    ):
        caps = info._gather_capabilities(images=[], host_arch="x86_64")
        priv = next(c for c in caps if c.label == "Privileges")
        assert priv.level == "info"
        assert "can elevate via daemon socket" in priv.value
