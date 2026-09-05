# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""The entry point: validate, decide whether root is needed, then dispatch.

`main()` does the argument work argparse cannot, because users are shown the
hand-written pages in `commands/help/` and never argparse's own text. So `-h` is
intercepted before parsing, an unknown first word is rejected with the help page
rather than a usage line, and `REQUIRED_ARGS` positionals are checked here (the check
uses `not`, which also catches the empty list an `nargs="*"` positional produces).
Unknown-argument detection reparses up to a `--` for `login` and `run`, since
everything after it belongs to the guest command.

Root policy is decided here and nowhere else. `help`, `search` and `daemon` never
elevate; `daemon` additionally refuses to elevate itself, because it is started by an
init system and self-elevation could recurse through the socket it serves. On Termux
`list` and `ps` read only /proc and container metadata so they stay unprivileged, and
`info` elevates only when root is already available. On Linux everything else
elevates, because containers live in root's data dir and a rootless read would look in
the wrong place.

Startup latency is a feature, so imports are lazy: handlers are `"module:function"`
strings resolved on dispatch, help pages and `elevate` are imported inside the branch
that needs them, and `constants.PROGRAM_VERSION` resolves through a module `__getattr__`.
Adding a top-level import here costs every invocation, including tab completion.

Termux drops `LD_PRELOAD` and `LD_LIBRARY_PATH` from the environment first: the Termux
shell sets a loader shim that must not follow this process into a chroot.

Everything below is expected to fail by raising a `ChrootDistroError`, which becomes a
one-line message and exit code 1. A bare `Exception` gets the same treatment with an
"unexpected error" prefix, so no traceback ever reaches a user.
"""

import importlib
import os
import signal
import sys
from collections.abc import Callable
from typing import Any

from chroot_distro.constants import IS_TERMUX, PROGRAM_NAME
from chroot_distro.exceptions import ChrootDistroError, RootRequiredError
from chroot_distro.message import crit_error, msg, set_quiet
from chroot_distro.parser import (
    ALIAS_TO_CANONICAL,
    REQUIRED_ARGS,
    build_parser,
    parse_cli_args,
)

# "module:function" refs; imported on dispatch (tests patch in callables).
_COMMAND_HANDLERS: dict[str, str | Callable] = {
    "install": "chroot_distro.commands.install:command_install",
    "remove": "chroot_distro.commands.remove:command_remove",
    "rename": "chroot_distro.commands.rename:command_rename",
    "reset": "chroot_distro.commands.reset:command_reset",
    "login": "chroot_distro.commands.login:command_login",
    "list": "chroot_distro.commands.list_cmd:command_list",
    "backup": "chroot_distro.commands.backup:command_backup",
    "restore": "chroot_distro.commands.restore:command_restore",
    "clear-cache": "chroot_distro.commands.clear_cache:command_clear_cache",
    "copy": "chroot_distro.commands.copy:command_copy",
    "sync": "chroot_distro.commands.sync:command_sync",
    "run": "chroot_distro.commands.run:command_run",
    "unmount": "chroot_distro.commands.unmount:command_unmount",
    "build": "chroot_distro.commands.build:command_build",
    "push": "chroot_distro.commands.push:command_push",
    "kill": "chroot_distro.commands.kill:command_kill",
    "ps": "chroot_distro.commands.ps:command_ps",
    "diff": "chroot_distro.commands.diff:command_diff",
    "search": "chroot_distro.commands.search:command_search",
    "setup": "chroot_distro.commands.setup:command_setup",
    "daemon": "chroot_distro.commands.daemon_cmd:command_daemon",
    "info": "chroot_distro.commands.info:command_info",
    "help": "chroot_distro.commands.help:command_help",
}


def _resolve_handler(canonical: str) -> Callable | None:
    handler = _COMMAND_HANDLERS.get(canonical)
    if handler is None or callable(handler):
        return handler
    module_name, _, func_name = handler.partition(":")
    resolved: Callable = getattr(importlib.import_module(module_name), func_name)
    return resolved


def _sigquit_to_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt()


def _ensure_root_user() -> None:
    """Ensure that we are running as root, elevating if necessary/possible.

    Unlike proot-distro (which is rootless), chroot-distro uses the host's
    native chroot and mount mechanisms, requiring root privileges.
    """
    if os.getuid() == 0:
        return

    from chroot_distro.elevate import elevate_or_die

    elevate_or_die()


def _dispatch_help(raw_args: list[str]) -> bool:
    """Render per-command help when -h/--help/--usage is given."""
    if len(raw_args) < 2 or raw_args[1] not in ("-h", "--help", "--usage"):
        return False
    from chroot_distro.commands.help import HELP_COMMANDS

    cmd = ALIAS_TO_CANONICAL.get(raw_args[0], raw_args[0])
    if cmd in HELP_COMMANDS:
        HELP_COMMANDS[cmd]()
        return True
    return False


def _reject_unknown_command(raw_args: list[str]) -> None:
    """Exit with help text when the first arg names no known command."""
    if not raw_args:
        return
    first = raw_args[0]
    if not first.startswith("-") and first not in _COMMAND_HANDLERS and first not in ALIAS_TO_CANONICAL:
        from chroot_distro.commands.help import command_help

        msg()
        crit_error(f"unknown command '{first}'.")
        command_help()
        msg()
        sys.exit(1)


def main() -> None:
    """CLI entry point.

    Validates the runtime environment, parses arguments, and dispatches
    to the chosen command's handler.
    """
    if IS_TERMUX:
        os.environ.pop("LD_PRELOAD", None)
        os.environ.pop("LD_LIBRARY_PATH", None)

    signal.signal(signal.SIGQUIT, _sigquit_to_keyboard_interrupt)

    if len(sys.argv) >= 2:
        ALIAS_TO_CANONICAL.get(sys.argv[1], sys.argv[1])

    if len(sys.argv) >= 2 and sys.argv[1] in ("--version", "-V"):
        from chroot_distro.constants import PROGRAM_VERSION

        print(f"{PROGRAM_NAME} {PROGRAM_VERSION}")
        sys.exit(0)

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help", "hel", "he", "h"):
        from chroot_distro.commands.help import command_help

        command_help()
        sys.exit(0)

    raw_args = sys.argv[1:]
    if _dispatch_help(raw_args):
        sys.exit(0)

    _reject_unknown_command(raw_args)

    parser = build_parser()
    args, unknown = parse_cli_args(parser, raw_args)

    command = args.command
    if command is None:
        from chroot_distro.commands.help import command_help

        msg()
        crit_error(f"unknown command '{raw_args[0]}'.")
        command_help()
        msg()
        sys.exit(1)

    assert command is not None
    canonical: str = ALIAS_TO_CANONICAL.get(command) or command

    if getattr(args, "help", False):
        from chroot_distro.commands.help import HELP_COMMANDS, command_help

        if canonical in HELP_COMMANDS:
            HELP_COMMANDS[canonical]()
        else:
            command_help()
        sys.exit(0)

    check_unknown = unknown
    if canonical in ("login", "run") and "--" in raw_args:
        sep_idx = raw_args.index("--")
        _, check_unknown = parse_cli_args(parser, raw_args[:sep_idx])
    if check_unknown:
        from chroot_distro.commands.help import HELP_COMMANDS

        bad = check_unknown[0]
        kind = "unrecognized option" if bad.startswith("-") else "unexpected argument"
        msg()
        crit_error(f"{kind}: '{bad}'.")
        if canonical in HELP_COMMANDS:
            HELP_COMMANDS[canonical]()
        msg()
        sys.exit(1)

    for arg_name, error_msg in REQUIRED_ARGS.get(canonical, []):
        # `not` (rather than `is None`) also catches the empty list that
        # nargs="*" positionals produce when no value is given.
        if not getattr(args, arg_name, None):
            from chroot_distro.commands.help import HELP_COMMANDS

            msg()
            crit_error(error_msg)
            if canonical in HELP_COMMANDS:
                HELP_COMMANDS[canonical]()
            sys.exit(1)

    if canonical != "list" and getattr(args, "quiet", False):
        set_quiet(True)

    # `search` is network-only. `list` and `ps` only read /proc and container
    # metadata, so they are exempt on Termux; on Linux containers are installed
    # by root and live in root's data dir, so they still elevate there to read
    # the right location. `info` elevates only when root is available, for the
    # kernel config, and runs rootless otherwise.
    if canonical == "daemon" and os.getuid() != 0:
        # The daemon is started by the init system and must already be
        # root; never self-elevate it (that could recurse through itself).
        crit_error("the daemon must be started as root (normally by your init system).")
        sys.exit(1)

    requires_root = False
    if canonical in ("help", "search", "daemon"):
        requires_root = False
    elif IS_TERMUX:
        if canonical == "info":
            from chroot_distro.elevate import is_root_available

            requires_root = is_root_available()
        elif canonical not in ("list", "ps"):
            requires_root = True
    else:
        requires_root = True

    if requires_root:
        try:
            _ensure_root_user()
        except RootRequiredError as e:
            msg()
            crit_error(str(e))
            msg()
            sys.exit(1)

    handler = _resolve_handler(canonical)
    if handler is None:
        crit_error(f"unknown command '{command}'.")
        sys.exit(1)

    try:
        handler(args)
    except ChrootDistroError as e:
        msg()
        crit_error(str(e))
        msg()
        sys.exit(1)
    except KeyboardInterrupt:
        msg()
        crit_error("Aborted by user.")
        msg()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(1)
    except NotImplementedError as e:
        msg()
        crit_error(str(e))
        msg()
        sys.exit(1)
    except Exception as e:
        msg()
        crit_error(f"unexpected error: {e}")
        msg()
        sys.exit(1)


if __name__ == "__main__":
    main()
