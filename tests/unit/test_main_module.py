import runpy
from unittest.mock import patch


def test_main_module_invokes_cli():
    # Executing the package as __main__ must call cli.main(). runpy runs it
    # in-process (under the __name__ == "__main__" guard) so coverage sees it.
    with patch("chroot_distro.cli.main") as mock_main, patch("sys.argv", ["chroot-distro"]):
        runpy.run_module("chroot_distro", run_name="__main__", alter_sys=True)
    mock_main.assert_called_once()
