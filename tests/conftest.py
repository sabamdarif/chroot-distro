import sys
from unittest.mock import MagicMock

# Stub Linux-only modules if not on Linux to allow tests to run on Windows/macOS
if sys.platform != "linux":
    # Mock fcntl
    if "fcntl" not in sys.modules:
        sys.modules["fcntl"] = MagicMock()

    # Mock pwd
    if "pwd" not in sys.modules:
        pwd_mock = MagicMock()
        pwd_mock.getpwuid.return_value = MagicMock(pw_name="root", pw_dir="/root")
        pwd_mock.getpwnam.return_value = MagicMock(pw_name="root", pw_dir="/root")
        sys.modules["pwd"] = pwd_mock

    # Mock grp
    if "grp" not in sys.modules:
        sys.modules["grp"] = MagicMock()

    # Mock termios
    if "termios" not in sys.modules:
        sys.modules["termios"] = MagicMock()

    # Mock os features missing on Windows
    import os
    if not hasattr(os, "getuid"):
        os.getuid = lambda: 1000
    if not hasattr(os, "getgid"):
        os.getgid = lambda: 1000
    if not hasattr(os, "getgroups"):
        os.getgroups = lambda: [1000]
    if not hasattr(os, "chown"):
        os.chown = lambda path, uid, gid: None

    # Mock signal features missing on Windows
    import signal
    for sig in ["SIGHUP", "SIGQUIT", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGALRM", "SIGCHLD"]:
        if not hasattr(signal, sig):
            setattr(signal, sig, 999)
