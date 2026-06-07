import argparse
import os
import signal
import sys
from typing import Any

from chroot_distro.commands.backup import command_backup
from chroot_distro.commands.build import command_build
from chroot_distro.commands.clear_cache import command_clear_cache
from chroot_distro.commands.copy import command_copy
from chroot_distro.commands.help import HELP_COMMANDS, command_help
from chroot_distro.commands.install import command_install
from chroot_distro.commands.list_cmd import command_list
from chroot_distro.commands.login import command_login
from chroot_distro.commands.push import command_push
from chroot_distro.commands.remove import command_remove
from chroot_distro.commands.rename import command_rename
from chroot_distro.commands.reset import command_reset
from chroot_distro.commands.restore import command_restore
from chroot_distro.commands.run import command_run
from chroot_distro.commands.sync import command_sync
from chroot_distro.commands.unmount import command_unmount
from chroot_distro.constants import IS_TERMUX, PROGRAM_NAME, PROGRAM_VERSION
from chroot_distro.exceptions import ChrootDistroError, RootRequiredError
from chroot_distro.message import crit_error, msg, set_quiet
from chroot_distro.parser import (
    ALIAS_TO_CANONICAL,
    REQUIRED_ARGS,
    build_parser,
    parse_cli_args,
)


def command_stub(args: argparse.Namespace) -> None:
    raise NotImplementedError(f"Command '{args.command}' is not yet implemented.")


_COMMAND_HANDLERS = {
    "install": command_install,
    "remove": command_remove,
    "rename": command_rename,
    "reset": command_reset,
    "login": command_login,
    "list": command_list,
    "backup": command_backup,
    "restore": command_restore,
    "clear-cache": command_clear_cache,
    "copy": command_copy,
    "sync": command_sync,
    "run": command_run,
    "unmount": command_unmount,
    "build": command_build,
    "push": command_push,
    "help": command_help,
}


def _sigquit_to_keyboard_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt()


def _ensure_root_user(no_elevate: bool = False, use_sudo: bool = False) -> None:
    """Ensure that we are running as root, elevating if necessary/possible.

    Unlike proot-distro (which is rootless), chroot-distro uses the host's
    native chroot and mount mechanisms, requiring root privileges.
    """
    if os.getuid() == 0:
        return

    if no_elevate:
        raise RootRequiredError(f"{PROGRAM_NAME} requires root privileges. Please run with sudo or as root.")

    from chroot_distro.elevate import elevate_or_die

    elevate_or_die(use_sudo=use_sudo)


def _dispatch_help(raw_args: list[str]) -> bool:
    """Render per-command help when -h/--help/--usage is given."""
    if len(raw_args) < 2 or raw_args[1] not in ("-h", "--help", "--usage"):
        return False
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
    signal.signal(signal.SIGQUIT, _sigquit_to_keyboard_interrupt)

    if len(sys.argv) >= 2:
        ALIAS_TO_CANONICAL.get(sys.argv[1], sys.argv[1])

    if len(sys.argv) >= 2 and sys.argv[1] in ("--version", "-V"):
        print(f"{PROGRAM_NAME} {PROGRAM_VERSION}")
        sys.exit(0)

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help", "hel", "he", "h"):
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
        msg()
        crit_error(f"unknown command '{raw_args[0]}'.")
        command_help()
        msg()
        sys.exit(1)

    assert command is not None
    canonical: str = ALIAS_TO_CANONICAL.get(command) or command

    if getattr(args, "help", False):
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
        bad = check_unknown[0]
        kind = "unrecognized option" if bad.startswith("-") else "unexpected argument"
        msg()
        crit_error(f"{kind}: '{bad}'.")
        if canonical in HELP_COMMANDS:
            HELP_COMMANDS[canonical]()
        msg()
        sys.exit(1)

    for arg_name, error_msg in REQUIRED_ARGS.get(canonical, []):
        if getattr(args, arg_name, None) is None:
            msg()
            crit_error(error_msg)
            if canonical in HELP_COMMANDS:
                HELP_COMMANDS[canonical]()
            sys.exit(1)

    if canonical != "list" and getattr(args, "quiet", False):
        set_quiet(True)

    # Root check requirement:
    # - In normal Linux: all commands require root except "help"
    # - In Termux: all commands require root except "list" and "help"
    requires_root = False
    if IS_TERMUX:
        if canonical not in ("list", "help"):
            requires_root = True
    elif canonical != "help":
        requires_root = True

    if requires_root:
        no_elevate = getattr(args, "no_elevate", False) or os.environ.get("CHROOT_DISTRO_NO_ELEVATE") == "1"
        use_sudo = getattr(args, "use_sudo", False) or os.environ.get("CHROOT_DISTRO_USE_SUDO") == "1"
        try:
            _ensure_root_user(no_elevate=no_elevate, use_sudo=use_sudo)
        except RootRequiredError as e:
            msg()
            crit_error(str(e))
            msg()
            sys.exit(1)

    handler = _COMMAND_HANDLERS.get(canonical)
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
