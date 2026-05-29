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
from chroot_distro.message import C, msg


def _make_help_fn(name):
    def help_fn():
        render_page(HELP_PAGES[name])
    return help_fn


# Map every command name to a zero-arg renderer.
HELP_COMMANDS = {name: _make_help_fn(name) for name in HELP_PAGES}


def command_help(args=None) -> None:
    """Render the top-level help page (no command argument)."""
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
        f"Run '{PROGRAM_NAME} <command> --help' for details on any command.",
        width,
    )

    section("QUICK START")
    paragraph(
        "Usage of generic distribution images is straightforward. "
        "Below is an example for Ubuntu 25.10:",
        width,
    )
    msg()
    shell_block(
        [f"{PROGRAM_NAME} install ubuntu:25.10",
         f"{PROGRAM_NAME} login ubuntu"], width,
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
        "If your terminal (theme) does not work well with colors, "
        "set this environment variable:",
        width,
    )
    msg()
    shell_block(["export CD_FORCE_NO_COLORS=true"], width)
    msg()
    paragraph(
        "To pull private Docker/OCI images, set credentials via "
        "CD_DOCKER_AUTH in 'username:password' format before "
        "running the install command:",
        width,
    )
    msg()
    shell_block(
        ["export CD_DOCKER_AUTH=user:password",
         f"{PROGRAM_NAME} install ghcr.io/myorg/private-image:tag"],
        width,
    )
    msg()
    paragraph(
        "Report utility issues to "
        "https://github.com/sabamdarif/chroot-distro/issues",
        width,
    )

    footer(width)


__all__ = ("HELP_COMMANDS", "command_help")
