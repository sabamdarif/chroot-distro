# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The `--json` envelope, held to one shape for every command that has the flag.

Each command builds its own payload, so the only thing keeping them consistent is
the envelope `message.emit_json` adds. These tests read the document each command
writes to stdout and say that every one of them carries `schema` and names
itself, which is what lets a consumer check one key before reading the rest.
"""

import contextlib
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from chroot_distro.commands import diff as diff_mod
from chroot_distro.commands import info as info_mod
from chroot_distro.commands import list_cmd
from chroot_distro.commands import ps as ps_mod
from chroot_distro.message import JSON_SCHEMA_VERSION


def _run_list(args=None):
    with (
        patch.object(list_cmd, "_iter_container_names", return_value=([], [])),
        patch.object(list_cmd, "_container_row", return_value=list_cmd._ContainerRow("a", "1 B", "x", "idle")),
    ):
        list_cmd.command_list(args or SimpleNamespace(quiet=False, verbose=False, json=True))


def _run_ps(args=None):
    with (
        patch.object(ps_mod, "active_sessions", return_value=[]),
        patch.object(ps_mod, "containers_with_active_pids", return_value={}),
    ):
        ps_mod.command_ps(args or SimpleNamespace(quiet=False, json=True))


def _run_info(args=None):
    with (
        patch.object(info_mod, "get_device_cpu_arch", return_value="aarch64"),
        patch.object(info_mod, "_gather_program_info", return_value={"program": "x"}),
        patch.object(info_mod, "_gather_host_info", return_value=info_mod._HostInfo("Linux", [])),
        patch.object(info_mod, "_gather_images", return_value=[]),
        patch.object(info_mod, "_gather_capabilities", return_value=[]),
        patch.object(info_mod, "_gather_kernel_support", return_value=[]),
        patch.object(info_mod, "supports_32bit", return_value=True),
    ):
        info_mod.command_info(args or MagicMock(json=True))


def _run_diff(args=None):
    @contextlib.contextmanager
    def _noop(*_a, **_k):
        yield

    with (
        patch.object(diff_mod.os.path, "isdir", return_value=True),
        patch.object(diff_mod.os.path, "isfile", return_value=True),
        patch.object(diff_mod, "ContainerLock", _noop),
        patch.object(diff_mod, "loading_line", _noop),
        patch.object(diff_mod, "_load_layer_digests", return_value=["sha256:abc"]),
        patch.object(diff_mod, "baseline_cache_is_valid", return_value=True),
        patch.object(diff_mod, "cached_baseline_from_layers", return_value={}),
        patch.object(diff_mod, "snapshot", return_value={}),
        patch.object(diff_mod, "diff_against_baseline", return_value=([], [], [])),
    ):
        diff_mod.command_diff(args or SimpleNamespace(container_name="demo", json=True))


_RUNNERS = {
    "list": _run_list,
    "ps": _run_ps,
    "info": _run_info,
    "diff": _run_diff,
}


@pytest.mark.parametrize("command", sorted(_RUNNERS))
def test_every_document_carries_the_envelope(command, capsys):
    _RUNNERS[command]()
    out = capsys.readouterr().out
    document = json.loads(out)
    assert document["schema"] == JSON_SCHEMA_VERSION
    assert document["command"] == command
    assert "\x1b" not in out, "a JSON document must not carry colour escapes"


@pytest.mark.parametrize("command", sorted(_RUNNERS))
def test_the_document_is_one_line(command, capsys):
    # A consumer may read a stream of these, so one document is one line.
    _RUNNERS[command]()
    assert capsys.readouterr().out.count("\n") == 1


def test_error_document_shares_the_envelope(capsys):
    from chroot_distro.message import emit_json_error

    emit_json_error("diff", "container 'x' is not installed.")
    document = json.loads(capsys.readouterr().out)
    assert document == {
        "schema": JSON_SCHEMA_VERSION,
        "command": "diff",
        "error": "container 'x' is not installed.",
    }


def test_emit_json_does_not_pass_through_the_tty_gate(capsys):
    # `msg` is suppressed while another process holds the tty; machine output
    # is the command's own result and must still be written.
    from chroot_distro.message import emit_json

    with patch("chroot_distro.message.tty_safe_for_writes", return_value=False):
        emit_json("list", {"containers": []})
    assert json.loads(capsys.readouterr().out)["containers"] == []