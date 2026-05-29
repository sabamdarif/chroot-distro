import typing

# Predefined ARG keys that are always visible without explicit
# declaration in the Dockerfile (subset of Docker's "predefined"
# build args).
PREDEFINED_ARGS = frozenset({
    "TARGETPLATFORM", "TARGETOS", "TARGETARCH", "TARGETVARIANT",
    "BUILDPLATFORM", "BUILDOS", "BUILDARCH", "BUILDVARIANT",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "FTP_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "ftp_proxy", "all_proxy",
})

# Instructions whose argument values undergo variable expansion before
# dispatch (everything except CMD/ENTRYPOINT/RUN exec-form payloads).
EXPANDS_VARS = frozenset({
    "ADD", "ARG", "ENV", "EXPOSE", "FROM", "LABEL", "STOPSIGNAL",
    "USER", "VOLUME", "WORKDIR", "COPY",
})

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
