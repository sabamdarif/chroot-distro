# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The argparse tree, plus the two tables `cli.py` enforces by hand.

One private sub-builder per command, all called from `build_parser`. Almost no
`help=` text is set, deliberately: users are shown the hand-written pages in
`commands/help/pages.py`, so argparse help here would be a second copy that drifts.
Each sub-parser carries `_cd_command`, which is how `_CdArgumentParser.error` knows
which page to render when a parse fails.

`REQUIRED_ARGS` and `ALIAS_TO_CANONICAL` live here but are applied in `cli.py`.
Positionals are declared with `nargs="*"` rather than as required, so a missing
argument reaches `cli.py` as an empty list and can be reported with the command's own
help page instead of argparse's usage line. Adding a command means adding to both
tables, or its aliases resolve to nothing and its missing arguments are not caught.

The `login` and `run` sub-parsers split off guest arguments at a literal `--`
before argparse can treat them as host arguments. Bare login command words
parsed before that separator come first in the guest command. The JSON
sub-parsers take only switches and positionals, so they can recognise a request
for JSON before argparse reports an error. `-V` defers the
`importlib.metadata` lookup to use time.
"""

import argparse
import sys
from collections.abc import Iterable
from typing import Any, NoReturn, TypeVar, cast, overload

from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.message import crit_error, emit_json_error, escape_controls, msg

_NamespaceT = TypeVar("_NamespaceT")


def strip_global_separator(argv: list[str]) -> list[str]:
    """Drop an initial `--` before the command token."""
    if len(argv) > 1 and argv[0] == "--" and not argv[1].startswith("-"):
        return argv[1:]
    return argv


class _LazyVersionAction(argparse.Action):
    """`-V/--version` that defers the importlib.metadata lookup to use time."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        from chroot_distro.constants import PROGRAM_VERSION

        parser.exit(message=f"{PROGRAM_NAME} {PROGRAM_VERSION}\n")


class _CdArgumentParser(argparse.ArgumentParser):
    """Parse host arguments and render errors with the command's help page."""

    _cd_command: str | None = None
    _json_requested = False

    @overload
    def parse_known_args(
        self, args: Iterable[str] | None = None, namespace: None = None
    ) -> tuple[argparse.Namespace, list[str]]: ...

    @overload
    def parse_known_args(self, args: Iterable[str] | None, namespace: _NamespaceT) -> tuple[_NamespaceT, list[str]]: ...

    @overload
    def parse_known_args(self, *, namespace: _NamespaceT) -> tuple[_NamespaceT, list[str]]: ...

    def parse_known_args(
        self, args: Iterable[str] | None = None, namespace: _NamespaceT | None = None
    ) -> tuple[argparse.Namespace | _NamespaceT, list[str]]:
        argv = list(sys.argv[1:] if args is None else args)
        if self._cd_command is None:
            argv = strip_global_separator(argv)
        sep_idx = argv.index("--") if "--" in argv else len(argv)
        split_guest = self._cd_command in ("login", "run") and sep_idx < len(argv)
        before_separator = argv[:sep_idx]
        previous_json = self._json_requested
        self._json_requested = self.get_default("json") is not None and any(
            token.partition("=")[0] in ("--j", "--js", "--jso", "--json") for token in before_separator
        )
        try:
            parse_namespace = argparse.Namespace() if namespace is None else namespace
            parsed, unknown = super().parse_known_args(before_separator if split_guest else argv, parse_namespace)
        finally:
            self._json_requested = previous_json
        if split_guest:
            guest_args = argv[sep_idx + 1 :]
            parsed_args = cast(argparse.Namespace, parsed)
            if self._cd_command == "login":
                parsed_args.login_cmd = parsed_args.login_cmd + guest_args
            else:
                parsed_args.run_args = guest_args
        return parsed, unknown

    # Python 3.10 removes attached `--` values as if they were positional separators.
    def _get_values(self, action: argparse.Action, arg_strings: list[str]) -> Any:
        if (
            sys.version_info < (3, 11)
            and action.option_strings
            and action.nargs in (None, argparse.OPTIONAL)
            and arg_strings == ["--"]
        ):
            value = self._get_value(action, arg_strings[0])
            self._check_value(action, value)
            return value
        return super()._get_values(action, arg_strings)

    def error(self, message: str) -> NoReturn:
        from chroot_distro.commands.help import HELP_COMMANDS

        message = escape_controls(message)
        if self._json_requested and self._cd_command:
            emit_json_error(self._cd_command, message)
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
    "kill": [("container_or_pid", "container name or PID is not specified.")],
    "diff": [("container_name", "container name is not specified.")],
    "search": [("term", "search term is not specified.")],
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
    "k": "kill",
    "stop": "kill",
    "find": "search",
    "se": "search",
    "version-info": "info",
    "nf": "info",
    "h": "help",
    "he": "help",
    "hel": "help",
}


def _add_login_or_run_common(p):
    """Options shared by both `login` and `run`."""
    p.add_argument("-u", "--user", default=None)
    _iso = p.add_mutually_exclusive_group()
    _iso.add_argument("--isolated", "--isolate", dest="isolated", action="store_true")
    _iso.add_argument("--minimal", action="store_true")
    p.add_argument("--shared-home", dest="shared_home", action="store_true")
    p.add_argument("--shared-tmp", dest="shared_tmp", action="store_true")
    p.add_argument(
        "--shared-display",
        dest="shared_display",
        action="store_true",
        help="Share X11, Wayland, sound, and D-Bus with the container",
    )
    p.add_argument(
        "--shared-x11",
        dest="shared_display",
        action="store_true",
        help="Alias for --shared-display (backward compatibility)",
    )
    p.add_argument("-b", "--bind", action="append", metavar="PATH[:PATH[:OPTIONS]]")
    p.add_argument("-w", "--work-dir", dest="work_dir", metavar="PATH")
    p.add_argument("--no-new-privs", dest="no_new_privs", action="store_true")
    p.add_argument("-e", "--env", action="append", metavar="VAR=VALUE")


def build_parser() -> _CdArgumentParser:
    """Construct the top-level argparse parser with every subcommand."""
    parser = _CdArgumentParser(
        prog=PROGRAM_NAME,
        description="Manage Linux chroot containers.",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-V", "--version", action=_LazyVersionAction)
    sub = parser.add_subparsers(dest="command")

    _help(sub)
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
    _kill(sub)
    _ps(sub)
    _diff(sub)
    _search(sub)
    _info(sub)

    return parser


def _help(sub):
    p = sub.add_parser("help", aliases=["hel", "he", "h"], add_help=False)
    p._cd_command = "help"
    p.add_argument("help_topic", nargs="?", metavar="COMMAND")
    p.add_argument("-h", "--help", action="store_true")


def _install(sub):
    p = sub.add_parser("install", aliases=["add", "i", "in", "ins"], add_help=False)
    p._cd_command = "install"
    p.add_argument("image_ref", nargs="*", default=None, metavar="IMAGE")
    name_grp = p.add_mutually_exclusive_group()
    name_grp.add_argument("-n", "--name", dest="custom_container_name", metavar="ALIAS")
    name_grp.add_argument("--override-alias", dest="custom_container_name", metavar="ALIAS")
    p.add_argument(
        "-a",
        "--architecture",
        dest="override_arch",
        metavar="ARCH",
    )
    p.add_argument("--allow-insecure", dest="insecure", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _remove(sub):
    p = sub.add_parser("remove", aliases=["rm"], add_help=False)
    p._cd_command = "remove"
    p.add_argument("container_name", nargs="*", default=None)
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
    vq = p.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true")
    vq.add_argument("-q", "--quiet", action="store_true")
    vq.add_argument("--json", action="store_true")


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
    p.add_argument("--build-cache", dest="build_cache", action="store_true")
    p.add_argument("--keep", dest="keep", metavar="SIZE", default=None)
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
    p.add_argument("--chown", default=None, metavar="USER[:GROUP]")
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
    p.add_argument("--chown", default=None, metavar="USER[:GROUP]")
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
        "--build-context",
        dest="build_contexts",
        action="append",
        default=[],
        metavar="name=VALUE",
    )
    p.add_argument(
        "-a",
        "--architecture",
        dest="override_arch",
        metavar="ARCH",
    )
    p.add_argument(
        "--platform",
        dest="platforms",
        action="append",
        default=[],
        metavar="LIST",
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
    p.add_argument(
        "--secret",
        dest="secrets",
        action="append",
        default=[],
        metavar="id=NAME[,src=PATH]",
    )
    p.add_argument(
        "--ssh",
        dest="ssh",
        action="append",
        nargs="?",
        const="default",
        default=[],
        metavar="ID[=SOCK]",
    )
    p.add_argument(
        "--export",
        dest="exports",
        action="append",
        default=[],
        metavar="type=local,dest=DIR | type=tar,dest=FILE",
    )
    p.add_argument(
        "--cache-from",
        dest="cache_from",
        action="append",
        default=[],
        metavar="type=local,src=DIR | type=registry,ref=REF",
    )
    p.add_argument(
        "--cache-to",
        dest="cache_to",
        action="append",
        default=[],
        metavar="type=local,dest=DIR | type=registry,ref=REF",
    )
    p.add_argument("--no-cache", dest="no_cache", action="store_true")
    p.add_argument(
        "--allow-insecure",
        dest="insecure",
        action="store_true",
        help="Allow plain-HTTP registries for --cache-from/--cache-to type=registry.",
    )
    p.add_argument(
        "--progress",
        dest="progress",
        choices=["auto", "plain", "tty", "rawjson"],
        default="auto",
    )
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
    p.add_argument("--allow-insecure", dest="insecure", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _run(sub):
    p = sub.add_parser("run", add_help=False)
    p._cd_command = "run"
    p.add_argument("container_name", nargs="?", default=None)
    _add_login_or_run_common(p)
    p.add_argument(
        "--entrypoint",
        dest="entrypoint",
        default=None,
        metavar="EXECUTABLE",
        help="Replace the image Entrypoint for this run (Cmd is cleared).",
    )
    p.add_argument(
        "-d",
        "--detach",
        dest="detach",
        action="store_true",
        help="Run the command in the background and return immediately.",
    )
    p.add_argument("--get-chroot-cmd", dest="get_chroot_cmd", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _unmount(sub):
    p = sub.add_parser("unmount", aliases=["umount", "um"], add_help=False)
    p._cd_command = "unmount"
    p.add_argument("container_name", nargs="?", default=None)
    p.add_argument("-h", "--help", action="store_true")


def _kill(sub):
    p = sub.add_parser("kill", aliases=["k", "stop"], add_help=False)
    p._cd_command = "kill"
    p.add_argument("container_or_pid", nargs="?", default=None)
    p.add_argument("-h", "--help", action="store_true")


def _ps(sub):
    p = sub.add_parser("ps", add_help=False)
    p._cd_command = "ps"
    qj = p.add_mutually_exclusive_group()
    qj.add_argument("-q", "--quiet", action="store_true")
    qj.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _diff(sub):
    p = sub.add_parser("diff", add_help=False)
    p._cd_command = "diff"
    p.add_argument("container_name", nargs="?", default=None)
    p.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _search(sub):
    p = sub.add_parser("search", aliases=["find", "se"], add_help=False)
    p._cd_command = "search"
    p.add_argument("term", nargs="?", default=None)
    p.add_argument("-l", "--limit", type=int, default=25, metavar="N")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-h", "--help", action="store_true")


def _info(sub):
    p = sub.add_parser("info", aliases=["version-info", "nf"], add_help=False)
    p._cd_command = "info"
    p.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
