"""Tests for the process-ancestry filter that keeps children of a tracked
session from being mislabelled 'untracked' by ``chroot-distro ps``."""

from __future__ import annotations

from unittest.mock import mock_open, patch

from chroot_distro.helpers import session


def test_read_ppid_parses_stat():
    # Field 2 (comm) may contain spaces/parens; PPID is the field after the
    # final ')'. Emulate a process whose name is "(weird )name)".
    stat = "4242 ((weird )name)) S 100 4242 100 0 -1 4194560 0 0"
    with patch("builtins.open", mock_open(read_data=stat)):
        assert session.read_ppid(4242) == 100


def test_read_ppid_missing_returns_none():
    with patch("builtins.open", side_effect=OSError("no such pid")):
        assert session.read_ppid(999999) is None


def test_child_of_tracked_session_is_recognised():
    # 200 -> 150 -> 100 (tracked). Walking the chain finds the tracked login.
    parents = {200: 150, 150: 100, 100: 1}
    with patch.object(session, "read_ppid", parents.get):
        assert session.has_tracked_ancestor(200, {100}) is True


def test_tracked_pid_itself_is_recognised():
    with patch.object(session, "read_ppid", lambda _pid: 1):
        assert session.has_tracked_ancestor(100, {100}) is True


def test_genuine_orphan_has_no_tracked_ancestor():
    parents = {200: 150, 150: 1}
    with patch.object(session, "read_ppid", parents.get):
        assert session.has_tracked_ancestor(200, {999}) is False


def test_ancestor_walk_stops_on_cycle():
    # A pathological parent cycle must not loop forever.
    parents = {200: 201, 201: 200}
    with patch.object(session, "read_ppid", parents.get):
        assert session.has_tracked_ancestor(200, {999}) is False


def test_ancestor_walk_stops_at_init():
    with patch.object(session, "read_ppid", lambda _pid: None):
        assert session.has_tracked_ancestor(1, {100}) is False
