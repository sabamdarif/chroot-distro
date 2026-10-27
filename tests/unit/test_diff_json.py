# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`diff` under `--json`, and its error contract.

The handler used to end a failure with `crit_error` plus `sys.exit`, which a
`--json` caller could not report. It raises `ChrootDistroError` now, so the one
`cli.main` error path produces both the stderr line and the document.
"""

import contextlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from chroot_distro.commands import diff as diff_mod
from chroot_distro.exceptions import ChrootDistroError


@contextlib.contextmanager
def _noop(*_a, **_k):
    yield


def _run(*, added=(), modified=(), deleted=(), json_mode=True):
    args = SimpleNamespace(container_name="demo", json=json_mode)
    with (
        patch.object(diff_mod.os.path, "isdir", return_value=True),
        patch.object(diff_mod.os.path, "isfile", return_value=True),
        patch.object(diff_mod, "ContainerLock", _noop),
        patch.object(diff_mod, "loading_line", _noop),
        patch.object(diff_mod, "_load_layer_digests", return_value=["sha256:abc"]),
        patch.object(diff_mod, "baseline_cache_is_valid", return_value=True),
        patch.object(diff_mod, "cached_baseline_from_layers", return_value={}),
        patch.object(diff_mod, "snapshot", return_value={}),
        patch.object(
            diff_mod,
            "diff_against_baseline",
            return_value=(list(added), list(modified), list(deleted)),
        ),
        patch.object(diff_mod, "msg") as mock_msg,
    ):
        diff_mod.command_diff(args)
    return mock_msg


def test_json_paths_are_absolute_and_sorted(capsys):
    _run(
        added=["etc/new", "etc/another"],
        modified=["usr/bin/x"],
        deleted=["root/.bashrc"],
    )
    document = json.loads(capsys.readouterr().out)
    assert document["container"] == "demo"
    assert document["added"] == ["/etc/another", "/etc/new"]
    assert document["modified"] == ["/usr/bin/x"]
    assert document["deleted"] == ["/root/.bashrc"]


def test_json_drops_mount_only_top_directories(capsys):
    _run(added=["proc/sys/kernel", "tmp/x", "etc/real"], modified=["dev/null"])
    document = json.loads(capsys.readouterr().out)
    assert document["added"] == ["/etc/real"]
    assert document["modified"] == []


def test_json_has_empty_lists_when_nothing_changed(capsys):
    _run()
    document = json.loads(capsys.readouterr().out)
    assert document["added"] == []
    assert document["modified"] == []
    assert document["deleted"] == []


def test_human_output_is_unchanged_without_the_flag(capsys):
    mock_msg = _run(added=["etc/new"], json_mode=False)
    assert capsys.readouterr().out == ""
    printed = [str(c.args[0]) for c in mock_msg.call_args_list if c.args]
    assert any("A " in line and "/etc/new" in line for line in printed)


def test_a_missing_container_raises_instead_of_exiting():
    args = SimpleNamespace(container_name="ghost", json=True)
    with patch.object(diff_mod.os.path, "isdir", return_value=False):
        with pytest.raises(ChrootDistroError, match="is not installed"):
            diff_mod.command_diff(args)


def test_a_missing_manifest_raises():
    args = SimpleNamespace(container_name="demo", json=True)
    with (
        patch.object(diff_mod.os.path, "isdir", return_value=True),
        patch.object(diff_mod.os.path, "isfile", return_value=False),
    ):
        with pytest.raises(ChrootDistroError, match="no image manifest"):
            diff_mod.command_diff(args)


def test_an_unreadable_manifest_raises():
    args = SimpleNamespace(container_name="demo", json=True)
    with (
        patch.object(diff_mod.os.path, "isdir", return_value=True),
        patch.object(diff_mod.os.path, "isfile", return_value=True),
        patch.object(diff_mod, "ContainerLock", _noop),
        patch.object(diff_mod, "_load_layer_digests", side_effect=ValueError("bad json")),
        pytest.raises(ChrootDistroError, match="failed to read manifest"),
    ):
        diff_mod.command_diff(args)


def test_a_manifest_without_layers_raises():
    args = SimpleNamespace(container_name="demo", json=True)
    with (
        patch.object(diff_mod.os.path, "isdir", return_value=True),
        patch.object(diff_mod.os.path, "isfile", return_value=True),
        patch.object(diff_mod, "ContainerLock", _noop),
        patch.object(diff_mod, "_load_layer_digests", return_value=[]),
        pytest.raises(ChrootDistroError, match="lists no image layers"),
    ):
        diff_mod.command_diff(args)