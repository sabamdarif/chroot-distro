import shlex
import typing

from chroot_distro.helpers.build_engine.errors import BuildError


def split_arg(value: typing.Any) -> tuple[str, str | None]:
    """Parse `ARG K[=V]` value text. Returns (key, default_or_None)."""
    if isinstance(value, list):
        value = " ".join(value)
    s = str(value).strip()
    if not s:
        return ("", None)
    if "=" in s:
        k, _, v = s.partition("=")
        v = v.strip()
        if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
            v = v[1:-1]
        return (k.strip(), v)
    return (s, None)


def split_operands(value: typing.Any, instr: dict[str, typing.Any]) -> list[str]:
    """shlex-split a shell-form instruction's operands, or raise BuildError.

    COPY/ADD's source and destination list, EXPOSE's ports and VOLUME's
    mount points are all written with shell quoting, and shlex answers an
    unbalanced quote or a trailing backslash with a ValueError. The
    Dockerfile is the user's own file, but `build` catches only BuildError
    and OSError, so one mistyped line ended the build in a traceback
    instead of naming the line that caused it.
    """
    try:
        return shlex.split(str(value))
    except ValueError as exc:
        raise BuildError(f"Cannot parse {instr['name']} at line {instr['lineno']}: {exc}.") from exc


def parse_kv_list(value: typing.Any) -> list[tuple[str, str]]:
    """Parse ENV/LABEL key=value pairs (with shell-like quoting)."""
    s = str(value).strip()
    if "=" not in s:
        # Legacy ENV form: `ENV KEY value` (no equals). Single pair.
        toks = s.split(None, 1)
        if len(toks) == 2:
            return [(toks[0], toks[1])]
        return [(s, "")]
    try:
        lex = shlex.shlex(s, posix=True)
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError as exc:
        raise BuildError(f"Cannot parse key=value list: {exc}") from exc
    pairs = []
    for t in tokens:
        if "=" not in t:
            continue
        k, _, v = t.partition("=")
        pairs.append((k, v))
    return pairs


def to_argv(instr: dict[str, typing.Any], default_shell: list[str]) -> list[str]:
    """Convert a CMD/ENTRYPOINT instruction into an argv list.

    Exec form: the value is already a list.
    Shell form: wrap the value with the default shell.
    """
    if instr["exec_form"]:
        return list(instr["value"])
    raw = str(instr["value"])
    return [*list(default_shell), raw]


def looks_like_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))


def is_tar_archive(path: str) -> bool:
    """Cheap signature-only check for tar / tar.gz / tar.bz2 / tar.xz."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(265)
    except OSError:
        return False
    if len(head) < 265:
        return False
    if head[257:263] == b"ustar\x00" or head[257:265] == b"ustar  \x00":
        return True
    if head[:3] == b"\x1f\x8b\x08":
        return True
    if head[:3] == b"BZh":
        return True
    return head[:6] == b"\xfd7zXZ\x00"
