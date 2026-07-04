import argparse

from chroot_distro.daemon import serve


def command_daemon(args: argparse.Namespace) -> None:
    """Run the group-gated privileged daemon (started by the init system)."""
    serve(persist=bool(getattr(args, "persist", False)))
