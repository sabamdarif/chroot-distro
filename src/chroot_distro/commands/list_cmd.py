import os

from chroot_distro.constants import CONTAINERS_DIR, PROGRAM_NAME
from chroot_distro.message import C, msg
from chroot_distro.paths import container_rootfs


def command_list(args) -> None:
    """List every container directory that contains a rootfs/."""
    quiet = getattr(args, "quiet", False)

    try:
        entries = sorted(
            e for e in os.listdir(CONTAINERS_DIR)
            if os.path.isdir(container_rootfs(e))
        )
    except OSError:
        entries = []

    if quiet:
        for name in entries:
            print(name)
        return

    msg()
    if not entries:
        msg(f"{C['YELLOW']}No containers are installed.{C['RST']}")
        msg()
        msg(f"{C['CYAN']}Install one with: "
            f"{C['GREEN']}{PROGRAM_NAME} install ubuntu:25.10{C['RST']}")
    else:
        msg(f"{C['CYAN']}Installed containers:{C['RST']}")
        msg()
        for name in entries:
            msg(f"  {C['CYAN']}* {C['GREEN']}{name}{C['RST']}")
        msg()
        msg(f"{C['CYAN']}Log in with: "
            f"{C['GREEN']}{PROGRAM_NAME} login <name>{C['RST']}")
    msg()
