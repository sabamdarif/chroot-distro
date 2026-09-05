"""Tests for --shared-display /run narrowing and socket discovery."""

from unittest.mock import patch

from chroot_distro.commands.login.bindings import get_bindings
from chroot_distro.helpers.display import (
    _socket_from_dbus_address,
    resolve_display_socket_binds,
)


def test_socket_from_dbus_address():
    assert _socket_from_dbus_address("unix:path=/run/user/1000/bus") == "/run/user/1000/bus"
    assert _socket_from_dbus_address("unix:path=/run/user/1000/bus,guid=abc") == "/run/user/1000/bus"
    assert _socket_from_dbus_address("tcp:host=localhost,port=1") is None


def test_resolve_display_socket_binds_returns_runtime_dir():
    env = {
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "WAYLAND_DISPLAY": "wayland-0",
        "PULSE_SERVER": "unix:/run/user/1000/pulse/native",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
    }
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000"),
        patch("os.path.exists", side_effect=lambda p: p.startswith("/run/user/1000")),
    ):
        binds = resolve_display_socket_binds(env)
    # The whole runtime dir is bound; its sockets come along via the
    # recursive bind, so they are not listed individually.
    assert binds == ["/run/user/1000"]


def test_resolve_display_socket_binds_adds_external_dbus():
    env = {
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/var/run/dbus/bus",
    }
    present = {"/run/user/1000", "/var/run/dbus/bus"}
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000"),
        patch("os.path.exists", side_effect=lambda p: p in present),
    ):
        binds = resolve_display_socket_binds(env)
    assert binds[0] == "/run/user/1000"
    # D-Bus socket outside the runtime dir is bound individually.
    assert "/var/run/dbus/bus" in binds


def test_resolve_display_socket_binds_adds_system_bus():
    env = {"XDG_RUNTIME_DIR": "/run/user/1000"}
    present = {"/run/user/1000", "/run/dbus/system_bus_socket"}
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", side_effect=lambda p: p == "/run/user/1000"),
        patch("os.path.exists", side_effect=lambda p: p in present),
        patch("os.path.realpath", side_effect=lambda p: p),
    ):
        binds = resolve_display_socket_binds(env)
    assert "/run/dbus/system_bus_socket" in binds


def test_resolve_display_socket_binds_no_runtime_dir():
    env = {"XDG_RUNTIME_DIR": "/run/user/1000"}
    with (
        patch("chroot_distro.helpers.display.resolve_invoking_uid", return_value=1000),
        patch("os.path.isdir", return_value=False),
        patch("os.path.exists", return_value=False),
    ):
        binds = resolve_display_socket_binds(env)
    assert binds == []


def test_get_bindings_binds_runtime_dir_with_shared_display():
    sockets = ["/run/user/1000"]
    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isdir", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_display=True,
            display_socket_binds=sockets,
        )
    srcs = {src for src, _ in binds}
    # The host's broad /run is never bound.
    assert "/run" not in srcs
    # The user runtime dir is bound and marked for rslave.
    assert "/run/user/1000" in srcs
    assert any(t.endswith("/run/user/1000") for t in rslave)


def test_get_bindings_never_binds_host_run():
    with (
        patch("os.path.exists", return_value=True),
        patch("chroot_distro.commands.login.bindings.IS_TERMUX", False),
    ):
        binds, rslave = get_bindings(
            rootfs="/fake/rootfs",
            minimal=False,
            isolated=False,
            shared_display=False,
        )
    srcs = {src for src, _ in binds}
    # Host /run is never bound, in any mode.
    assert "/run" not in srcs
    assert not any(t.endswith("/run") for t in rslave)
