# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Turn one instruction's value text into the pieces a handler wants.

Text work only, shared by the handlers so the same quoting rules apply
everywhere: `split_args` for `ARG K[=V] ...`, `split_operands` for the shell-form
lists COPY, ADD, EXPOSE and VOLUME carry, `parse_kv_list` for ENV and LABEL
(including the legacy `ENV KEY value` form), `to_argv` for CMD and ENTRYPOINT,
`parse_duration_ns` for HEALTHCHECK's intervals.

Every ValueError shlex can raise becomes a `BuildError` naming the line, because
`build` catches only BuildError and OSError and one mistyped quote would
otherwise end the build in a traceback.

`is_tar_header` sits here rather than with ADD because it is a signature test
and nothing more: it takes bytes, not a name, so ADD's auto-extract sniffs the
inode it already holds open.
"""

import re
import shlex
import typing

from chroot_distro.helpers.build_engine.errors import BuildError

# One whitespace-separated word of an ARG value, with a quoted run counting as
# part of the word it sits in (`ARG A="x y" B=2` is two words).
_ARG_WORD_RE = re.compile(r"""(?:[^\s"']|"[^"]*"|'[^']*')+""")


def split_args(value: typing.Any) -> list[tuple[str, str | None]]:
    """Parse an `ARG K[=V] [K[=V]...]` value. One (key, default_or_None) per name.

    One ARG line may declare several names, which is what Docker accepts, so the
    result is a list: read as a single pair, `ARG A=1 B=2` declared one variable
    named A whose default was the text `1 B=2`.
    """
    if isinstance(value, list):
        value = " ".join(value)
    return [_split_one_arg(word) for word in _ARG_WORD_RE.findall(str(value))]


def _split_one_arg(word: str) -> tuple[str, str | None]:
    if "=" not in word:
        return (word, None)
    k, _, v = word.partition("=")
    if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
        v = v[1:-1]
    return (k, v)


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


# How much of a file the signature check below needs: the ustar magic sits at
# offset 257 and runs to 265.
TAR_HEADER_BYTES = 265


def is_tar_header(head: bytes) -> bool:
    """True when *head* opens a tar / tar.gz / tar.bz2 / tar.xz stream.

    A signature-only check, and it takes the bytes rather than a name: the one
    caller (ADD's auto-extract) already holds a descriptor on the file, so it
    sniffs the very inode it is about to read instead of resolving the path a
    second time and hoping for the same file.
    """
    if len(head) < TAR_HEADER_BYTES:
        return False
    if head[257:263] == b"ustar\x00" or head[257:265] == b"ustar  \x00":
        return True
    if head[:3] == b"\x1f\x8b\x08":
        return True
    if head[:3] == b"BZh":
        return True
    return head[:6] == b"\xfd7zXZ\x00"
