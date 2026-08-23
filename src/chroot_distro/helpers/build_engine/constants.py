import typing

# Predefined ARG keys that are always visible without explicit
# declaration in the Dockerfile (subset of Docker's "predefined"
# build args).
PREDEFINED_ARGS = frozenset(
    {
        "TARGETPLATFORM",
        "TARGETOS",
        "TARGETARCH",
        "TARGETVARIANT",
        "BUILDPLATFORM",
        "BUILDOS",
        "BUILDARCH",
        "BUILDVARIANT",
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

# Instructions whose argument values undergo variable expansion before
# dispatch (everything except CMD/ENTRYPOINT/RUN exec-form payloads).
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


# Env-var prefixes that change what the *host-side* exec does rather than
# what the container sees.
_HOST_EXEC_PREFIXES = ("LD_",)


def is_host_exec_var(key: str) -> bool:
    """True when *key* is read by the host side of a RUN step, not by the guest.

    A RUN step execs the host's `chroot` binary and the environment it is
    given is passed on to the command inside the new root, so one dict serves
    two masters: to the host's dynamic loader, an `LD_*` name means "a setting
    for the process that has not entered the rootfs yet".

    The rule is about provenance, not about the name. A value the invoking
    user set for *this* invocation -- a variable in their shell, `--build-arg`
    on the command line -- is their own choice about their own command. A
    value out of a file describing an image is not: an image's config is a
    stranger's outright, and an ENV line is a statement about the image,
    carried in a Dockerfile as often copied from upstream as written (Docker's
    own builder never reads one into the builder's environment). Callers use
    this to refuse the second kind; nothing here filters the first.

    What makes it more than tidiness is where the exec starts from. `chroot`
    is handed `.` and the child fchdirs onto the stage rootfs before the exec,
    so a *relative* LD_LIBRARY_PATH or LD_AUDIT entry is resolved by the host
    loader against that rootfs -- a directory an earlier RUN step had the run
    of. A step dropping a library under `lib/`, then `ENV LD_LIBRARY_PATH=lib`
    on any later step, is the guest's code running as the invoking user
    outside any container, with nothing of the host bound in to blame.
    """
    return key.startswith(_HOST_EXEC_PREFIXES)
