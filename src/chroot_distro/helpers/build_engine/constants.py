# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Tables the engine consults before it dispatches an instruction.

`PREDEFINED_ARGS` and `EXPANDS_VARS` say which ARG keys exist without a
declaration and which instruction values are variable-expanded. Both follow
Docker's documented behaviour and are not derived from anything here, so a
difference from Docker is a difference in these sets. The automatic
TARGET*/BUILD* values are not among them: Docker keeps those in the global
scope, so they come from the build's platforms (`engine.platform_args`) and a
stage sees one only after a bare `ARG NAME` re-declares it.

`needs_chroot` is asked once, before any step runs, so a Dockerfile with no RUN
never pays for a chroot. It looks through an ONBUILD wrapper because the
instruction one carries runs like any other.

`is_host_exec_var` is the only policy in the file, and its own docstring is
where the reason lives.
"""

import typing

# Predefined ARG keys that are always visible without explicit
# declaration in the Dockerfile, and whose value comes from the invoking
# environment (Docker's "predefined" build args).
PREDEFINED_ARGS = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "FTP_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "ftp_proxy",
        "all_proxy",
    }
)

# Instructions whose value is variable-expanded before dispatch, which is
# Docker's documented list. RUN is deliberately absent: its command is the
# shell's to expand, while its flags are expanded like any other (engine
# ._dispatch), and CMD and ENTRYPOINT are expanded by nothing at all.
EXPANDS_VARS = frozenset(
    {
        "ADD",
        "ARG",
        "ENV",
        "EXPOSE",
        "FROM",
        "LABEL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
        "COPY",
    }
)

# Instructions that require executing `chroot` against the rootfs.
CHROOT_REQUIRED_INSTRUCTIONS = frozenset({"RUN"})


def needs_chroot(instructions: list[dict[str, typing.Any]]) -> bool:
    """Return True iff any instruction (including ONBUILD <inner>) is RUN."""
    for instr in instructions:
        name = instr.get("name", "")
        if name in CHROOT_REQUIRED_INSTRUCTIONS:
            return True
        if name == "ONBUILD":
            inner = instr.get("value")
            if isinstance(inner, dict) and inner.get("name") in CHROOT_REQUIRED_INSTRUCTIONS:
                return True
    return False


# Env-var prefixes that decide how a loader resolves libraries, rather than
# saying anything the program being run reads for itself.
_HOST_EXEC_PREFIXES = ("LD_",)


def is_host_exec_var(key: str) -> bool:
    """True when *key* aims a dynamic loader, so an image's config may not set it.

    An `LD_*` name is not a setting for the command that carries it: it is an
    instruction to the loader that starts that command, and `LD_PRELOAD` or
    `LD_AUDIT` puts code of the setter's choosing into every process the value
    reaches.

    The rule is about provenance, not about the name. A value the invoking
    user set for *this* invocation (a variable in their shell, `--build-arg` on
    the command line) is their own choice about their own command. A
    value out of a file describing an image is not: an image's config is a
    stranger's outright, and an ENV line is a statement about the image,
    carried in a Dockerfile as often copied from upstream as written (Docker's
    own builder never reads one into the builder's environment). Callers use
    this to refuse the second kind; nothing here filters the first.
    """
    return key.startswith(_HOST_EXEC_PREFIXES)
