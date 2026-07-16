from unittest.mock import MagicMock, patch

from chroot_distro.commands.list_cmd import (
    _ContainerRow,
    _format_table,
    _read_image_source,
    command_list,
)


def test_command_list_empty():
    with (
        patch("chroot_distro.commands.list_cmd._iter_container_names", return_value=([], [])),
        patch("chroot_distro.commands.list_cmd.msg") as mock_msg,
        patch("chroot_distro.message.C", dict.fromkeys(["YELLOW", "CYAN", "GREEN", "RST"], "")),
    ):
        args = MagicMock()
        args.quiet = False
        command_list(args)
        mock_msg.assert_any_call("No containers are installed.")


def test_command_list_with_items():
    rows = [
        _ContainerRow("alpine", "12.0 MiB", "alpine:3.21 (aarch64)", "idle"),
        _ContainerRow("debian", "250.5 MiB", "debian:bookworm (x86_64)", "in use (PID 99: login)"),
    ]
    with (
        patch("chroot_distro.commands.list_cmd._iter_container_names", return_value=(["alpine", "debian"], [])),
        patch("chroot_distro.commands.list_cmd._container_row", side_effect=rows),
        patch("chroot_distro.commands.list_cmd.loading_line") as mock_loading,
        patch("chroot_distro.commands.list_cmd.msg") as mock_msg,
        patch(
            "chroot_distro.message.C",
            {
                "YELLOW": "",
                "CYAN": "",
                "GREEN": "",
                "RST": "",
                "BCYAN": "",
            },
        ),
    ):
        mock_loading.return_value.__enter__.return_value = lambda _text: None
        args = MagicMock()
        args.quiet = False
        command_list(args)
        mock_loading.assert_called_once()
        printed = [str(c.args[0]) for c in mock_msg.call_args_list if c.args]
        assert any("NAME" in line and "SIZE" in line and "SOURCE" in line for line in printed)
        assert any("alpine" in line and "12.0 MiB" in line for line in printed)
        assert any("in use (PID 99: login)" in line for line in printed)


def test_command_list_quiet():
    with (
        patch("chroot_distro.commands.list_cmd._iter_container_names", return_value=(["alpine", "debian"], ["broken"])),
        patch("builtins.print") as mock_print,
    ):
        args = MagicMock()
        args.quiet = True
        command_list(args)
        mock_print.assert_any_call("alpine")
        mock_print.assert_any_call("debian")
        # Interrupted installs are not usable containers; scripts consuming
        # `list -q` must never see them.
        for call in mock_print.call_args_list:
            assert call.args[0] != "broken"


def test_read_image_source_from_manifest(tmp_path, monkeypatch):
    containers = tmp_path / "containers"
    name = "demo"
    rootfs = containers / name / "rootfs"
    rootfs.mkdir(parents=True)
    manifest = containers / name / "manifest.json"
    manifest.write_text(
        '{"image_ref": "ubuntu:24.04", "arch": "aarch64"}',
        encoding="utf-8",
    )
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))
    assert _read_image_source(name) == "ubuntu:24.04 (aarch64)"


def test_read_image_source_permission_denied(monkeypatch):
    import errno

    monkeypatch.setattr("chroot_distro.commands.list_cmd.os.path.isfile", lambda _p: True)
    monkeypatch.setattr("chroot_distro.commands.list_cmd._ensure_manifest_readable", lambda _p: None)

    def _deny_open(*_args, **_kwargs):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("builtins.open", _deny_open)
    assert _read_image_source("alpine") == "alpine"


def test_read_image_source_without_manifest(tmp_path, monkeypatch):
    containers = tmp_path / "containers"
    name = "plain"
    (containers / name / "rootfs").mkdir(parents=True)
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))
    assert _read_image_source(name) == "local archive"


def test_format_table_aligns_columns():
    rows = [
        _ContainerRow("a", "1.0 MiB", "alpine:3", "idle"),
        _ContainerRow("long-name", "10.0 GiB", "ghcr.io/org/image:tag (x86_64)", "in use (PID 1: login)"),
    ]
    with patch("chroot_distro.message.C", dict.fromkeys(["GREEN", "CYAN", "YELLOW", "BCYAN", "RST"], "")):
        lines = _format_table(rows)
    assert len(lines) == 3
    assert "NAME" in lines[0]
    assert "SOURCE" in lines[0]
    assert "STATUS" in lines[0]
    assert "long-name" in lines[2]
    assert "ghcr.io/org/image:tag" in lines[2]


def test_iter_container_names_permission_denied(monkeypatch):
    import errno

    import chroot_distro.commands.list_cmd as list_cmd

    def _deny_listdir(*_args, **_kwargs):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("os.listdir", _deny_listdir)

    mock_warn = MagicMock()
    monkeypatch.setattr(list_cmd, "warn", mock_warn)

    CONTAINERS_DIR = list_cmd.CONTAINERS_DIR
    _iter_container_names = list_cmd._iter_container_names
    assert _iter_container_names() == ([], [])
    mock_warn.assert_called_once_with(f"Permission denied: cannot read containers directory '{CONTAINERS_DIR}'")


def _make_container(containers, name, *, incomplete=False):
    (containers / name / "rootfs").mkdir(parents=True)
    if incomplete:
        (containers / name / ".install-incomplete").touch()


def test_iter_container_names_separates_incomplete(tmp_path, monkeypatch):
    """Leftovers from interrupted installs must not be listed as installed."""
    containers = tmp_path / "containers"
    _make_container(containers, "alpine")
    _make_container(containers, "ubuntu", incomplete=True)
    monkeypatch.setattr("chroot_distro.commands.list_cmd.CONTAINERS_DIR", str(containers))
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))

    from chroot_distro.commands.list_cmd import _iter_container_names

    installed, incomplete = _iter_container_names()
    assert installed == ["alpine"]
    assert incomplete == ["ubuntu"]


def test_command_list_mentions_interrupted_installs():
    with (
        patch("chroot_distro.commands.list_cmd._iter_container_names", return_value=([], ["ubuntu"])),
        patch("chroot_distro.commands.list_cmd.msg") as mock_msg,
        patch("chroot_distro.message.C", dict.fromkeys(["YELLOW", "CYAN", "GREEN", "RST"], "")),
    ):
        args = MagicMock()
        args.quiet = False
        command_list(args)
        printed = [str(c.args[0]) for c in mock_msg.call_args_list if c.args]
        assert any("No containers are installed." in line for line in printed)
        assert any("Interrupted install(s)" in line and "ubuntu" in line for line in printed)


def test_installed_containers_excludes_incomplete(tmp_path, monkeypatch):
    containers = tmp_path / "containers"
    _make_container(containers, "alpine")
    _make_container(containers, "debian", incomplete=True)
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(containers))

    from chroot_distro.paths import installed_containers

    assert installed_containers() == ["alpine"]
