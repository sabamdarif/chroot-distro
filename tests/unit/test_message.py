import os
import sys
from unittest.mock import patch

from chroot_distro.message import (
    _init_colors,
    crit_error,
    is_quiet,
    log_error,
    log_info,
    msg,
    set_quiet,
    warn,
)


def test_init_colors():
    # If isatty is False, colors should be empty
    with patch("sys.stderr.isatty", return_value=False):
        colors = _init_colors()
        assert all(v == "" for v in colors.values())

    # If isatty is True and no force no colors env var, colors should have values
    with patch("sys.stderr.isatty", return_value=True), patch.dict(os.environ, {}, clear=True):
        colors = _init_colors()
        assert colors["RED"] != ""

    # If force no colors env var is set, colors should be empty
    with patch("sys.stderr.isatty", return_value=True), patch.dict(os.environ, {"CD_FORCE_NO_COLORS": "1"}):
        colors = _init_colors()
        assert all(v == "" for v in colors.values())


def test_quiet_mode():
    set_quiet(True)
    assert is_quiet() is True
    set_quiet(False)
    assert is_quiet() is False


@patch("chroot_distro.message.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
@patch("sys.stderr.flush")
def test_msg(mock_flush, mock_write, mock_tty_safe):
    with patch("builtins.print") as mock_print:
        msg("hello", "world")
        mock_write.assert_called_once_with("\r\033[K")
        mock_flush.assert_called_once()
        mock_print.assert_called_once_with("hello", "world", file=sys.stderr)


@patch("chroot_distro.message.tty_safe_for_writes", return_value=False)
def test_msg_not_safe(mock_tty_safe):
    with patch("builtins.print") as mock_print:
        msg("hello")
        mock_print.assert_not_called()


@patch("chroot_distro.message.msg")
def test_logging(mock_msg):
    # Setup quiet mode false
    set_quiet(False)

    from chroot_distro.message import _COLORS
    with patch("chroot_distro.message.C", _COLORS):
        log_info("info msg")
        mock_msg.assert_any_call("\x1b[0m\x1b[34m[\x1b[0m\x1b[32m*\x1b[0m\x1b[34m] \x1b[0m\x1b[36minfo msg\x1b[0m")

        log_error("error msg")
        mock_msg.assert_any_call("\x1b[0m\x1b[34m[\x1b[0m\x1b[31m!\x1b[0m\x1b[34m] \x1b[0m\x1b[36merror msg\x1b[0m")

        warn("warning msg")
        mock_msg.assert_any_call("\x1b[0m\x1b[1m\x1b[33mWarning: \x1b[0m\x1b[33mwarning msg\x1b[0m")

        crit_error("critical msg")
        mock_msg.assert_any_call("\x1b[0m\x1b[1m\x1b[31mError: \x1b[0m\x1b[31mcritical msg\x1b[0m")

        # Test log_info is no-op when quiet is True
        mock_msg.reset_mock()
        set_quiet(True)
        log_info("info msg")
        mock_msg.assert_not_called()

        # log_error is still called when quiet is True
        log_error("error msg")
        mock_msg.assert_called_once()

