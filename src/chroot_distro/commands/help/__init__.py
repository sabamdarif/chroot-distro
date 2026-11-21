# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`help` as a command, plus the per-command `--help` renderers `cli` dispatches to.

`HELP_COMMANDS` maps every key in `pages.HELP_PAGES` to a zero-argument renderer
for both `--help` and `help COMMAND`. Without a topic, `command_help` combines
the `TOP_COMMANDS` table with quick-start and troubleshooting prose.
"""

from chroot_distro.commands.help.pages import HELP_PAGES, TOP_COMMANDS
from chroot_distro.commands.help.render import (
    commands_block,
    footer,
    paragraph,
    render_page,
    section,
    shell_block,
    term_width,
    usage_line,
)
from chroot_distro.constants import PROGRAM_NAME, RUNTIME_DIR
from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.message import C, msg
from chroot_distro.parser import ALIAS_TO_CANONICAL


def _make_help_fn(name):
    def help_fn():
        render_page(HELP_PAGES[name])

    return help_fn


# Map every command name to a zero-arg renderer.
HELP_COMMANDS = {name: _make_help_fn(name) for name in HELP_PAGES}


def command_help(args=None) -> None:
    """Render the requested command's help or the front page."""
    topic: str | None = getattr(args, "help_topic", None)
    if topic is not None:
        render = HELP_COMMANDS.get(ALIAS_TO_CANONICAL.get(topic, topic))
        if render is None:
            raise ChrootDistroError(f"unknown help topic {topic!a}.")
        render()
        return

    width = term_width()

    section("USAGE")
    usage_line("[COMMAND] [ARGUMENTS]", width)

    section("DESCRIPTION")
    paragraph(
        "Chroot-Distro is a wrapper utility for native chroot and bind mountings. "
        "This utility provides a convenient way for working with Linux "
        "containers, leveraging support of Docker registries to provide "
        "distributions of any kind.",
        width,
    )

    section("COMMANDS")
    commands_block(TOP_COMMANDS, width)

    section("GETTING HELP")
    paragraph(
        f"Run '{PROGRAM_NAME} help <command>' or '{PROGRAM_NAME} <command> --help' for details. "
        "Use -V or --version to print the version.",
        width,
    )

    section("QUICK START")
    paragraph(
        "Usage of generic distribution images is straightforward. Below is an example for Ubuntu 25.10:",
        width,
    )
    msg()
    shell_block(
        [f"{PROGRAM_NAME} install ubuntu:25.10", f"{PROGRAM_NAME} login ubuntu"],
        width,
    )
    msg()
    paragraph(
        "If you no longer need a specific container, delete it with:",
        width,
    )
    msg()
    shell_block([f"{PROGRAM_NAME} remove ubuntu"], width)
    msg()
    paragraph(
        "You can discover existing images on Docker Hub "
        "(https://hub.docker.com/) or other places on the Internet. "
        "You can also build your own image from a Dockerfile with "
        f"'{PROGRAM_NAME} build'.",
        width,
    )

    section("DATA LOCATION")
    msg(f"  {C['YELLOW']}{RUNTIME_DIR}{C['RST']}")

    section("TROUBLESHOOTING")
    paragraph(
        "If your terminal (theme) does not work well with colors, set this environment variable:",
        width,
    )
    msg()
    shell_block(["export CD_FORCE_NO_COLORS=true"], width)
    msg()
    paragraph(
        "To pull private Docker/OCI images, set credentials via "
        "CD_DOCKER_AUTH in 'username:password' format before "
        "running the install command. The password half is a "
        "personal access token on most registries, GHCR included:",
        width,
    )
    msg()
    shell_block(
        ["export CD_DOCKER_AUTH=user:personal-access-token", f"{PROGRAM_NAME} install ghcr.io/myorg/private-image:tag"],
        width,
    )
    msg()
    paragraph(
        "Report utility issues to https://github.com/sabamdarif/chroot-distro/issues",
        width,
    )

    footer(width)


__all__ = ("HELP_COMMANDS", "command_help")
