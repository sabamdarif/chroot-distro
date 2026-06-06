import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from chroot_distro.constants import PROGRAM_NAME, PROGRAM_VERSION
from chroot_distro.message import crit_error, msg


class _CdArgumentParser(argparse.ArgumentParser):
    """Argparse subclass that defers errors to the CLI dispatcher."""

    _cd_command: str | None = None

    def error(self, message: str) -> NoReturn:
        # Late import to avoid import cycle
        from chroot_distro.commands.help import HELP_COMMANDS

        msg()
        crit_error(message)
        if self._cd_command and self._cd_command in HELP_COMMANDS:
            HELP_COMMANDS[self._cd_command]()
        msg()
        sys.exit(1)


# Maps each canonical command to required (arg_name, error_message) pairs.
REQUIRED_ARGS = {
    "install": [("image_ref", "Docker image reference or archive path/URL is not specified.")],
    "remove": [("container_name", "container name is not specified.")],
    "rename": [
        ("orig_name", "the original container name is not specified."),
        ("new_name", "the new container name is not specified."),
    ],
    "reset": [("container_name", "container name is not specified.")],
    "login": [("container_name", "container name is not specified.")],
    "backup": [("container_name", "container name is not specified.")],
    "copy": [("source", "source path is not specified."), ("destination", "destination path is not specified.")],
    "sync": [("source", "source path is not specified."), ("destination", "destination path is not specified.")],
    "run": [("container_name", "container name is not specified.")],
    "push": [("image_ref", "image reference is not specified.")],
    "unmount": [("container_name", "container name is not specified.")],
}


# Aliases for the canonical command names.
ALIAS_TO_CANONICAL = {
    "add": "install",
    "i": "install",
    "in": "install",
    "ins": "install",
    "rm": "remove",
    "sh": "login",
    "li": "list",
    "ls": "list",
    "bak": "backup",
    "bkp": "backup",
    "clear": "clear-cache",
    "cl": "clear-cache",
    "cp": "copy",
    "umount": "unmount",
    "um": "unmount",
    "h": "help",
    "he": "help",
    "hel": "help",
}


def _apply_post_separators(canonical: str, raw_args: list[str], args: argparse.Namespace) -> None:
    """Set login_cmd / run_args from tokens after a literal '--'."""
    if "--" not in raw_args:
        return
    sep_idx = raw_args.index("--")
    tail = raw_args[sep_idx + 1 :]
    if canonical == "login":
        args.login_cmd = tail
    elif canonical == "run":
        args.run_args = tail


def parse_cli_args(
    parser: _CdArgumentParser,
    raw_args: Sequence[str],
    namespace: argparse.Namespace | None = None,
) -> tuple[argparse.Namespace, list[str]]:
    """Parse argv and apply login/run ``--`` post-processing."""
    argv = list(raw_args)
    ns, unknown = argparse.ArgumentParser.parse_known_args(parser, argv, namespace)
    assert ns is not None
    command = getattr(ns, "command", None)
    if command:
        canonical = ALIAS_TO_CANONICAL.get(command, command)
        if canonical in ("login", "run"):
            _apply_post_separators(canonical, argv, ns)
            if "--" in argv and "--" in unknown:
                unknown = unknown[: unknown.index("--")]
    return ns, unknown


def _add_login_or_run_common(p):
    """Options shared by both `login` and `run`."""
    p.add_argument("-u", "--user", default="root")
    _iso = p.add_mutually_exclusive_group()
    _iso.add_argument("--isolated", action="store_true")
    _iso.add_argument("--minimal", action="store_true")
    p.add_argument("--shared-home", dest="shared_home", action="store_true")
    p.add_argument("--shared-tmp", dest="shared_tmp", action="store_true")
    p.add_argument("--shared-display", dest="shared_display", action="store_true",
                   help="Share X11, Wayland, sound, and D-Bus with the container")
    p.add_argument("--shared-x11", dest="shared_display", action="store_true",
                   help="Alias for --shared-display (backward compatibility)")
    p.add_argument("-b", "--bind", action="append", metavar="PATH[:PATH]")
    p.add_argument("--hostname", metavar="STRING")
    p.add_argument("-w", "--work-dir", dest="work_dir", metavar="PATH")
    p.add_argument("-e", "--env", action="append", metavar="VAR=VALUE")


def build_parser() -> _CdArgumentParser:
    """Construct the top-level argparse parser with every subcommand."""
    parser = _CdArgumentParser(
        prog=PROGRAM_NAME,
        description="Manage Linux chroot containers.",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {PROGRAM_VERSION}")
    parser.add_argument("--no-elevate", action="store_true")
    parser.add_argument("--use-sudo", action="store_true")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("help", aliases=["hel", "he", "h"], add_help=False)

    _install(sub)
    _remove(sub)
    _rename(sub)
    _reset(sub)
    _login(sub)
    _list(sub)
    _backup(sub)
    _restore(sub)
    _clear_cache(sub)
    _copy(sub)
    _sync(sub)
    _build(sub)
    _push(sub)
    _run(sub)
    _unmount(sub)

    return parser


def _install(sub):
    p = sub.add_parser("install", aliases=["add", "i", "in", "ins"], add_help=False)
    p._cd_command = "install"
    p.add_argument("image_ref", nargs="?", default=None, metavar="IMAGE")
    name_grp = p.add_mutually_exclusive_group()
    name_grp.add_argument("-n", "--name", dest="custom_container_name", metavar="ALIAS")
    name_grp.add_argument("--override-alias", dest="custom_container_name", metavar="ALIAS")
    p.add_argument(
        "-a",
        "--architecture",
        dest="override_arch",
        metavar="ARCH",
    )
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _remove(sub):
    p = sub.add_parser("remove", aliases=["rm"], add_help=False)
    p._cd_command = "remove"
    p.add_argument("container_name", nargs="?", default=None)
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _rename(sub):
    p = sub.add_parser("rename", add_help=False)
    p._cd_command = "rename"
    p.add_argument("orig_name", nargs="?", default=None)
    p.add_argument("new_name", nargs="?", default=None)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _reset(sub):
    p = sub.add_parser("reset", add_help=False)
    p._cd_command = "reset"
    p.add_argument("container_name", nargs="?", default=None)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _login(sub):
    p = sub.add_parser("login", aliases=["sh"], add_help=False)
    p._cd_command = "login"
    p.add_argument("container_name", nargs="?", default=None)
    _add_login_or_run_common(p)
    p.add_argument("--get-chroot-cmd", dest="get_chroot_cmd", action="store_true")
    p.add_argument("login_cmd", nargs="*")
    p.add_argument("-h", "--help", action="store_true")


def _list(sub):
    p = sub.add_parser("list", aliases=["li", "ls"], add_help=False)
    p._cd_command = "list"
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")


def _backup(sub):
    p = sub.add_parser("backup", aliases=["bak", "bkp"], add_help=False)
    p._cd_command = "backup"
    p.add_argument("container_name", nargs="?", default=None)
    p.add_argument("-o", "--output", metavar="FILE")
    p.add_argument(
        "-c",
        "--compress",
        dest="compression",
        choices=["gzip", "bzip2", "xz", "none"],
        metavar="TYPE",
    )
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _restore(sub):
    p = sub.add_parser("restore", add_help=False)
    p._cd_command = "restore"
    p.add_argument("archive", nargs="?")
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _clear_cache(sub):
    p = sub.add_parser("clear-cache", aliases=["clear", "cl"], add_help=False)
    p._cd_command = "clear-cache"
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _copy(sub):
    p = sub.add_parser("copy", aliases=["cp"], add_help=False)
    p._cd_command = "copy"
    p.add_argument("source", nargs="?", default=None)
    p.add_argument("destination", nargs="?", default=None)
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-m", "--move", action="store_true")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _sync(sub):
    p = sub.add_parser("sync", add_help=False)
    p._cd_command = "sync"
    p.add_argument("source", nargs="?", default=None)
    p.add_argument("destination", nargs="?", default=None)
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-c", "--checksum", action="store_true")
    p.add_argument("-d", "--delete", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _build(sub):
    p = sub.add_parser("build", add_help=False)
    p._cd_command = "build"
    p.add_argument("path", nargs="?", default=".", metavar="PATH")
    p.add_argument("-f", "--file", dest="dockerfile", metavar="PATH")
    p.add_argument(
        "-t",
        "--tag",
        dest="tags",
        action="append",
        default=[],
        metavar="REF",
    )
    p.add_argument(
        "--build-arg",
        dest="build_args",
        action="append",
        default=[],
        metavar="K=V",
    )
    p.add_argument(
        "-a",
        "--architecture",
        dest="override_arch",
        metavar="ARCH",
    )
    p.add_argument(
        "--target",
        dest="target_stage",
        metavar="STAGE",
    )
    p.add_argument(
        "-o",
        "--output",
        dest="outputs",
        action="append",
        default=[],
        metavar="FILE",
    )
    p.add_argument(
        "--install-as",
        dest="install_as",
        metavar="NAME",
    )
    p.add_argument("--no-cache", dest="no_cache", action="store_true")
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _push(sub):
    p = sub.add_parser("push", add_help=False)
    p._cd_command = "push"
    p.add_argument("image_ref", nargs="?", default=None, metavar="IMAGE")
    p.add_argument(
        "-a",
        "--architecture",
        dest="override_arch",
        metavar="ARCH",
    )
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _run(sub):
    p = sub.add_parser("run", add_help=False)
    p._cd_command = "run"
    p.add_argument("container_name", nargs="?", default=None)
    _add_login_or_run_common(p)
    p.add_argument("--get-chroot-cmd", dest="get_chroot_cmd", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _unmount(sub):
    p = sub.add_parser("unmount", aliases=["umount", "um"], add_help=False)
    p._cd_command = "unmount"
    p.add_argument("container_name", nargs="?", default=None)
    p.add_argument("-h", "--help", action="store_true")
