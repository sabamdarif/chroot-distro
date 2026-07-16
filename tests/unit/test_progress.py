from unittest.mock import MagicMock, patch

from chroot_distro.progress import (
    ByteCounter,
    clear_bar,
    draw_bytes_bar,
    draw_count_bar,
    fmt_size,
    loading_line,
    progress_active,
)


def test_fmt_size():
    assert fmt_size(500) == "500 B"
    assert fmt_size(1024) == "1.0 KiB"
    assert fmt_size(1024 * 1024) == "1.0 MiB"
    assert fmt_size(1024 * 1024 * 1024) == "1.0 GiB"


def test_byte_counter():
    mock_fh = MagicMock()
    mock_fh.read.return_value = b"12345"
    bc = ByteCounter(mock_fh)
    assert bc.read(5) == b"12345"
    assert bc.count == 5

    buf = bytearray(5)
    mock_fh.readinto.return_value = 5
    assert bc.readinto(buf) == 5
    assert bc.count == 10


def test_progress_active():
    with patch("chroot_distro.progress.is_quiet", return_value=False):
        assert progress_active() is True
    with patch("chroot_distro.progress.is_quiet", return_value=True):
        assert progress_active() is False


@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
@patch("sys.stderr.flush")
def test_draw_bytes_bar_tty(mock_flush, mock_write, mock_tty_safe, mock_active):
    from chroot_distro.message import _COLORS

    with patch("sys.stderr.isatty", return_value=True), patch("chroot_distro.progress.C", _COLORS):
        # TTY with total
        draw_bytes_bar(50, 100, label="test", noun="downloaded")
        mock_write.assert_called_with(
            "\r\x1b[0m\x1b[34m[\x1b[0m\x1b[32m*\x1b[0m\x1b[34m] \x1b[0m\x1b[36mtest: [##########----------]  50%  50 B / 100 B\x1b[K\x1b[0m"
        )
        mock_flush.assert_called()

        mock_write.reset_mock()
        # TTY without total
        draw_bytes_bar(50, 0, label="test", noun="downloaded")
        mock_write.assert_called_with(
            "\r\x1b[0m\x1b[34m[\x1b[0m\x1b[32m*\x1b[0m\x1b[34m] \x1b[0m\x1b[36mtest: 50 B downloaded...\x1b[K\x1b[0m"
        )


@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
@patch("sys.stderr.flush")
def test_draw_bytes_bar_non_tty(mock_flush, mock_write, mock_tty_safe, mock_active):
    from chroot_distro.progress import _last_non_tty_bytes, _last_non_tty_pct

    _last_non_tty_pct.clear()
    _last_non_tty_bytes.clear()

    with patch("sys.stderr.isatty", return_value=False):
        # 1. Total > 0 path
        # First print (done = 0): should print
        draw_bytes_bar(0, 100, label="dl", noun="downloaded")
        assert mock_write.call_count == 1
        last_arg = mock_write.call_args[0][0]
        assert "Downloaded 0 B / 100 B" in last_arg
        assert "\r" not in last_arg
        assert "\x1b[K" not in last_arg

        # Small update (done = 5 / 5%): should be throttled (no print)
        mock_write.reset_mock()
        draw_bytes_bar(5, 100, label="dl", noun="downloaded")
        mock_write.assert_not_called()

        # Update reaching 10% (done = 10): should print
        mock_write.reset_mock()
        draw_bytes_bar(10, 100, label="dl", noun="downloaded")
        assert mock_write.call_count == 1
        assert "Downloaded 10 B / 100 B" in mock_write.call_args[0][0]

        # Final print (done = 100): should print
        mock_write.reset_mock()
        draw_bytes_bar(100, 100, label="dl", noun="downloaded")
        assert mock_write.call_count == 1
        assert "Downloaded 100 B / 100 B" in mock_write.call_args[0][0]
        # Should clear the tracking key
        assert ("dl", "downloaded") not in _last_non_tty_pct

        # 2. Total = 0 path
        mock_write.reset_mock()
        draw_bytes_bar(0, 0, label="dl", noun="downloaded")
        assert mock_write.call_count == 1
        assert "Downloaded 0 B" in mock_write.call_args[0][0]

        # Small byte update (100 B): throttled
        mock_write.reset_mock()
        draw_bytes_bar(100, 0, label="dl", noun="downloaded")
        mock_write.assert_not_called()

        # Big byte update (11 MiB): prints
        mock_write.reset_mock()
        draw_bytes_bar(11 * 1024 * 1024, 0, label="dl", noun="downloaded")
        assert mock_write.call_count == 1
        assert "Downloaded 11.0 MiB" in mock_write.call_args[0][0]


@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
@patch("sys.stderr.flush")
def test_draw_count_bar_non_tty(mock_flush, mock_write, mock_tty_safe, mock_active):
    from chroot_distro.progress import _last_non_tty_pct

    _last_non_tty_pct.clear()

    with patch("sys.stderr.isatty", return_value=False):
        # First print: should print
        draw_count_bar(0, 100, label="sync", unit="files")
        assert mock_write.call_count == 1
        assert "Processed 0 / 100 files" in mock_write.call_args[0][0]

        # Small update: throttled
        mock_write.reset_mock()
        draw_count_bar(1, 100, label="sync", unit="files")
        mock_write.assert_not_called()

        # Different key combo: should print
        mock_write.reset_mock()
        draw_count_bar(0, 20, label="other", unit="files")
        assert mock_write.call_count == 1


@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
def test_clear_bar(mock_write, mock_tty_safe, mock_active):
    with patch("sys.stderr.isatty", return_value=True):
        clear_bar()
        mock_write.assert_called_once_with("\r\x1b[K")

    mock_write.reset_mock()
    with patch("sys.stderr.isatty", return_value=False):
        clear_bar()
        mock_write.assert_not_called()


@patch("chroot_distro.progress.progress_active", return_value=True)
@patch("chroot_distro.progress.tty_safe_for_writes", return_value=True)
@patch("sys.stderr.write")
def test_loading_line_non_tty(mock_write, mock_tty_safe, mock_active):
    with patch("sys.stderr.isatty", return_value=False), loading_line("Testing status") as update:
        # Should write initial message
        assert mock_write.call_count == 1
        assert "Testing status" in mock_write.call_args[0][0]

        mock_write.reset_mock()
        # Send same message, should be throttled/deduplicated
        update("Testing status")
        mock_write.assert_not_called()

        # Send different message, should print
        update("New status")
        assert mock_write.call_count == 1
        assert "New status" in mock_write.call_args[0][0]
