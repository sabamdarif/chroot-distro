from unittest.mock import MagicMock, patch

from chroot_distro.commands.list_cmd import command_list


def test_command_list_empty():
    with patch("os.listdir", return_value=[]), \
         patch("chroot_distro.commands.list_cmd.msg") as mock_msg, \
         patch("chroot_distro.message.C", dict.fromkeys(["YELLOW", "CYAN", "GREEN", "RST"], "")):
        args = MagicMock()
        args.quiet = False
        command_list(args)
        mock_msg.assert_any_call("No containers are installed.")


def test_command_list_with_items():
    with patch("os.listdir", return_value=["alpine", "debian"]), \
         patch("os.path.isdir", return_value=True), \
         patch("chroot_distro.commands.list_cmd.msg") as mock_msg, \
         patch("chroot_distro.message.C", dict.fromkeys(["YELLOW", "CYAN", "GREEN", "RST"], "")):
        args = MagicMock()
        args.quiet = False
        command_list(args)
        mock_msg.assert_any_call("  * alpine")
        mock_msg.assert_any_call("  * debian")



def test_command_list_quiet():
    with patch("os.listdir", return_value=["alpine", "debian"]), \
         patch("os.path.isdir", return_value=True), \
         patch("builtins.print") as mock_print:
        args = MagicMock()
        args.quiet = True
        command_list(args)
        mock_print.assert_any_call("alpine")
        mock_print.assert_any_call("debian")
