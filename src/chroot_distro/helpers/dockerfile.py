# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Parse a Dockerfile into instruction records.

Parsing only: nothing here executes, opens or resolves anything, and every
value comes back as text. `helpers/build_engine/` decides what an instruction
means, so a value this module cannot make sense of is returned rather than
rejected. The two errors it does raise are structural, an unknown instruction
name and an unterminated here-doc body, because neither leaves a record a
consumer could act on.

A Dockerfile is untrusted input, and three of its features change how the rest
of the file is read, which is why they are settled here and not in the engine:
the `escape` directive picks the continuation character (only a backslash or a
backtick, anything else is dropped and the backslash assumed), the directive
zone ends at the first line that is not a recognised `# key=value` (a duplicate
key ends it too and becomes an ordinary comment), and a here-doc on ADD, COPY
or RUN consumes raw lines up to its closing tag, so those lines are body and
never instructions.

Two record fields need a check before use. `value` is a list only when
`exec_form` is true, which happens when the value parses as a JSON array of
strings and never otherwise; `flags["mount"]` is a list only when the flag
repeated, since `--mount` is the one repeatable flag and every other one is
last-writer-wins. An ONBUILD record carries the wrapped inner record as its
`value`, and that inner record's `raw` is the trigger *as an image config stores
it*: no leading ONBUILD, here-doc bodies appended, because whoever builds FROM
the image parses that text back as a Dockerfile line of their own.

`expand_vars` keeps unset and empty distinct: a None in the env mapping means
unset, which is what `${VAR-default}` and `${VAR+value}` test, while `:-` and
`:+` test for a non-empty value. `:?` and `?` are bash-isms and expand as
plain lookups.
"""

import json
import logging
import re
import shlex
import typing

log = logging.getLogger(__name__)

# All Dockerfile instructions, per
# https://docs.docker.com/reference/dockerfile/. MAINTAINER is
# deprecated but still common in the wild; we accept it.
_INSTRUCTIONS: frozenset[str] = frozenset(
    {
        "ADD",
        "ARG",
        "CMD",
        "COPY",
        "ENTRYPOINT",
        "ENV",
        "EXPOSE",
        "FROM",
        "HEALTHCHECK",
        "LABEL",
        "MAINTAINER",
        "ONBUILD",
        "RUN",
        "SHELL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    }
)

# Instructions that may carry a here-doc body (<<TAG ... TAG).
_HEREDOC_INSTRUCTIONS: frozenset[str] = frozenset({"ADD", "COPY", "RUN"})

# Instructions an ONBUILD may not wrap: another ONBUILD (chaining), and the two
# that answer for the build rather than for the image it produces. Docker
# refuses all three.
_ONBUILD_FORBIDDEN: frozenset[str] = frozenset({"ONBUILD", "FROM", "MAINTAINER"})

# Parser-directive names recognised at the top of a Dockerfile. All
# other `# k=v` lines after the first non-directive line become
# normal comments.
_DIRECTIVES: frozenset[str] = frozenset({"syntax", "escape", "check"})


class DockerfileSyntaxError(Exception):
    """Raised when the Dockerfile cannot be parsed."""


def parse_dockerfile(text: str | bytes) -> tuple[dict[str, str], list[dict[str, typing.Any]]]:
    """Parse Dockerfile content into (directives, instructions).

    directives is a dict of recognised parser directives (keys: 'syntax',
    'escape', 'check'). instructions is an ordered list of records:

        {
            "name":       str,         # upper-case instruction name
            "flags":      dict,        # --key=value flags before the value
            "value":      str | list,  # raw value, or list when exec form
            "exec_form":  bool,        # True iff value parsed as JSON array
            "heredocs":   list,        # list of {"tag", "strip_indent", "expand", "body"}
            "lineno":     int,         # 1-based source line of the first token
            "raw":        str,         # joined (continuation-merged) source
        }
    """
    text_str = text.decode("utf-8", errors="replace") if not isinstance(text, str) else text

    text_str = text_str.replace("\r\n", "\n").replace("\r", "\n")
    if text_str.startswith("\ufeff"):
        text_str = text_str[1:]

    raw_lines = text_str.split("\n")

    directives, directive_end = _parse_directives(raw_lines)
    escape_char = directives.get("escape", "\\") or "\\"
    if escape_char not in ("\\", "`"):
        # Spec only allows backslash or backtick; treat anything else as
        # an ordinary comment and fall back to backslash.
        escape_char = "\\"
        directives.pop("escape", None)

    instructions = _parse_instructions(raw_lines, directive_end, escape_char)
    return directives, instructions


_DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


def _parse_directives(raw_lines: list[str]) -> tuple[dict[str, str], int]:
    """Collect leading `# key=value` parser directives.

    Stops at the first non-blank, non-directive-comment line. Returns
    (directives_dict, index_of_first_post_directive_line).
    """
    directives = {}
    idx = 0
    n = len(raw_lines)
    while idx < n:
        line = raw_lines[idx]
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        if not stripped.startswith("#"):
            break
        inner = stripped[1:]
        m = _DIRECTIVE_RE.match(inner)
        if not m:
            break
        key = m.group(1).lower()
        if key not in _DIRECTIVES:
            break
        if key in directives:
            # Spec: a duplicate directive ends the directive zone and the
            # duplicate is treated as a comment.
            break
        directives[key] = m.group(2).strip()
        idx += 1
    return directives, idx


# A flag at the start of a value, e.g. --from=builder or --chmod=755.
# Flag values are non-space tokens; quoted values are handled by an
# explicit pre-pass before this matcher runs.
_FLAG_RE = re.compile(r"^\s*--([A-Za-z][A-Za-z0-9_-]*)(?:=(\S*))?(?=\s|$)")

# A here-doc opener: <<TAG, <<-TAG, <<"TAG", <<'TAG', <<-'TAG', ...
# The optional dash means "strip leading tabs from body and closing tag"
# in the spec; we honour that during body collection.
_HEREDOC_RE = re.compile(r"""<<(-?)(["']?)([A-Za-z_][A-Za-z0-9_]*)\2""")


def _parse_instructions(raw_lines: list[str], start_idx: int, escape_char: str) -> list[dict[str, typing.Any]]:
    instructions = []
    n = len(raw_lines)
    i = start_idx

    while i < n:
        raw_line = raw_lines[i]
        line_no = i + 1
        stripped = raw_line.lstrip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("#"):
            i += 1
            continue

        # Accumulate continuations. Comments and blank lines between
        # continued segments are skipped, matching Docker's behaviour.
        accumulated_parts = [raw_line]
        cur = raw_line
        while _ends_with_escape(cur, escape_char):
            accumulated_parts[-1] = _strip_trailing_escape(accumulated_parts[-1], escape_char)
            i += 1
            while i < n:
                nxt = raw_lines[i]
                nxt_lstripped = nxt.lstrip()
                if not nxt_lstripped:
                    i += 1
                    continue
                if nxt_lstripped.startswith("#"):
                    i += 1
                    continue
                break
            if i >= n:
                cur = ""
                break
            cur = raw_lines[i]
            accumulated_parts.append(cur)

        accumulated = " ".join(p.strip() for p in accumulated_parts).strip()
        if not accumulated:
            i += 1
            continue

        m = re.match(r"^\s*(\S+)\s*(.*)$", accumulated)
        if not m:
            i += 1
            continue
        name = m.group(1).upper()
        rest = m.group(2)

        if name not in _INSTRUCTIONS:
            raise DockerfileSyntaxError(f"Unknown instruction '{name}' at line {line_no}.")

        # ONBUILD carries another instruction, which is recorded as an
        # ordinary instruction and wrapped below.
        is_onbuild = name == "ONBUILD"
        if is_onbuild:
            name, rest = _onbuild_inner(rest, line_no)

        flags, rest = _parse_flags(rest)
        value = rest.strip()

        heredocs = []
        here_tags = _extract_heredoc_tags(value) if name in _HEREDOC_INSTRUCTIONS else []
        # Past the instruction's own line first, then one body after another:
        # each starts where the one before it stopped, which is the line after
        # its closing tag, so a second `<<TAG` does not lose its first line.
        i += 1
        for strip_indent, expand, tag in here_tags:
            body, i = _collect_heredoc_body(raw_lines, i, tag, strip_indent)
            heredocs.append(
                {
                    "tag": tag,
                    "strip_indent": strip_indent,
                    "expand": expand,
                    "body": body,
                }
            )

        exec_form, parsed_value = _try_exec_form(value)

        record: dict[str, typing.Any] = {
            "name": name,
            "flags": flags,
            "value": parsed_value if exec_form else value,
            "exec_form": exec_form,
            "heredocs": heredocs,
            "lineno": line_no,
            "raw": _onbuild_expression(accumulated, heredocs) if is_onbuild else accumulated,
        }

        if is_onbuild:
            instructions.append(
                {
                    "name": "ONBUILD",
                    "flags": {},
                    "value": record,  # the wrapped inner instruction
                    "exec_form": False,
                    "heredocs": [],
                    "lineno": line_no,
                    "raw": accumulated,
                }
            )
        else:
            instructions.append(record)

    return instructions


_ONBUILD_PREFIX_RE = re.compile(r"(?i)^\s*ONBUILD\s+")


def _onbuild_inner(rest: str, line_no: int) -> tuple[str, str]:
    """Split the instruction an ONBUILD wraps off *rest*. (name, remainder)."""
    m = re.match(r"^\s*(\S+)\s*(.*)$", rest)
    if not m:
        raise DockerfileSyntaxError(f"ONBUILD without inner instruction at line {line_no}.")
    inner_name = m.group(1).upper()
    if inner_name in _ONBUILD_FORBIDDEN:
        raise DockerfileSyntaxError(f"'{inner_name}' is not allowed as an ONBUILD trigger at line {line_no}.")
    if inner_name not in _INSTRUCTIONS:
        raise DockerfileSyntaxError(f"Invalid ONBUILD inner instruction '{inner_name}' at line {line_no}.")
    return inner_name, m.group(2)


def _onbuild_expression(accumulated: str, heredocs: list[dict[str, typing.Any]]) -> str:
    """The trigger text an ONBUILD records, as an image config stores one.

    Whoever builds FROM the image parses this back as a Dockerfile line, so the
    leading ONBUILD has to go (a trigger that kept it would read as
    `ONBUILD ONBUILD`) and a here-doc body has to travel with it (a `RUN <<EOF`
    with nothing after it is an unterminated body).
    """
    expression = _ONBUILD_PREFIX_RE.sub("", accumulated)
    for heredoc in heredocs:
        expression += "\n" + heredoc["body"] + heredoc["tag"]
    return expression


def _ends_with_escape(line: str, escape_char: str) -> bool:
    """True if `line` ends with the escape character (continuation)."""
    s = line.rstrip()
    if not s:
        return False
    if not s.endswith(escape_char):
        return False
    # Detect an escaped escape character ("\\\\" with escape='\\'):
    # an odd number of trailing escapes means continuation; an even
    # number means a literal trailing escape.
    cnt = 0
    j = len(s) - 1
    while j >= 0 and s[j] == escape_char:
        cnt += 1
        j -= 1
    return (cnt % 2) == 1


def _strip_trailing_escape(line: str, escape_char: str) -> str:
    """Remove the continuation escape (and any trailing whitespace)."""
    s = line.rstrip()
    if s.endswith(escape_char):
        s = s[:-1]
    return s.rstrip()


# Flags that may legally repeat on one instruction (RUN --mount). Repeats
# collect into a list; every other flag keeps last-writer-wins semantics.
_REPEATABLE_FLAGS = frozenset({"mount"})


def _record_flag(flags: dict[str, typing.Any], key: str, val: str) -> None:
    if key in _REPEATABLE_FLAGS and key in flags:
        existing = flags[key]
        if isinstance(existing, list):
            existing.append(val)
        else:
            flags[key] = [existing, val]
    else:
        flags[key] = val


def _parse_flags(text: str) -> tuple[dict[str, typing.Any], str]:
    """Pull leading --key[=value] flags off `text`.

    Returns (flags_dict, remaining_text). Flag values that contain
    spaces must be quoted with shlex syntax (`--chown="user:group"`),
    and we use shlex's POSIX mode to strip the quotes; un-quoted flag
    values stop at the next whitespace token. Values are strings, except
    repeatable flags (--mount) which become a list when repeated.
    """
    flags: dict[str, typing.Any] = {}
    while True:
        m = _FLAG_RE.match(text)
        if not m:
            break
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else ""
        # If the matched value contains quote chars that shlex would
        # strip, re-parse a single token via shlex to recover the
        # unquoted form.
        if "=" in m.group(0):
            after_eq = m.group(0).split("=", 1)[1]
            if after_eq and after_eq[0] in ('"', "'"):
                try:
                    rest_after = text[m.start() + m.group(0).index("=") + 1 :]
                    lex = shlex.shlex(rest_after, posix=True)
                    lex.whitespace_split = True
                    lex.commenters = ""
                    val = next(iter(lex))
                    consumed = m.start() + m.group(0).index("=") + 1 + _shlex_consumed_len(rest_after, val)
                    _record_flag(flags, key, val)
                    text = text[consumed:]
                    continue
                except (StopIteration, ValueError) as exc:
                    log.debug("Failed to parse flag with shlex: %s", exc)
        _record_flag(flags, key, val)
        text = text[m.end() :]
    return flags, text


def _shlex_consumed_len(source: str, parsed_token: str) -> int:
    """Best-effort: count source bytes that shlex consumed for one token."""
    if not source:
        return 0
    quote = source[0]
    if quote in ('"', "'"):
        i = 1
        while i < len(source) and source[i] != quote:
            # Honour POSIX backslash-escape inside double quotes.
            if quote == '"' and source[i] == "\\" and i + 1 < len(source):
                i += 2
                continue
            i += 1
        return i + 1
    return len(parsed_token)


def _extract_heredoc_tags(value: str) -> list[tuple[bool, bool, str]]:
    """Return [(strip_indent, expand, tag_name), ...] for here-doc openers.

    A quoted tag (`<<"EOF"`) means the body is taken literally, an unquoted one
    that `$VAR` in it expands, which is the shell's rule and Docker's. Only the
    COPY/ADD side acts on it: a RUN body is the shell's to expand.
    """
    tags = []
    for m in _HEREDOC_RE.finditer(value):
        tags.append((bool(m.group(1)), not m.group(2), m.group(3)))
    return tags


def _collect_heredoc_body(raw_lines: list[str], start_i: int, tag: str, strip_indent: bool) -> tuple[str, int]:
    """Read raw lines until the line that exactly matches `tag`.

    With strip_indent (i.e. <<-TAG), leading tabs are stripped from
    every body line and from the closing-tag line before comparison.

    Returns (body_text_with_trailing_newline, idx_one_past_closing_tag).
    """
    body: list[str] = []
    i = start_i
    n = len(raw_lines)
    while i < n:
        line = raw_lines[i]
        cmp_line = line.lstrip("\t") if strip_indent else line
        if cmp_line == tag or cmp_line.rstrip() == tag:
            return "\n".join(body) + ("\n" if body else ""), i + 1
        body.append(line.lstrip("\t") if strip_indent else line)
        i += 1
    raise DockerfileSyntaxError(f"Unterminated here-doc body for tag '{tag}'.")


def _try_exec_form(value: str) -> tuple[bool, list[str] | None]:
    """Detect JSON-array exec form. Returns (is_exec_form, parsed_list_or_None)."""
    s = value.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return False, None
    try:
        parsed = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return False, None
    if not isinstance(parsed, list):
        return False, None
    if not all(isinstance(x, str) for x in parsed):
        return False, None
    return True, parsed


def expand_vars(text: str, env: dict[str, str | None]) -> str:
    r"""Expand $VAR, ${VAR}, ${VAR:-default}, ${VAR-default},
    ${VAR:+value}, ${VAR+value} against the given env mapping.

    Unknown variables expand to the empty string. Unset-vs-empty
    distinction is preserved: a None entry in `env` means "unset",
    while an empty string means "set but empty" (relevant for the
    `:-` / `:+` operators).

    A leading backslash escapes the following character (so `\$FOO`
    is treated as a literal dollar sign followed by FOO).
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            next_char = text[i + 1]
            if next_char in ("$", "\\"):
                out.append(next_char)
                i += 2
                continue
            out.append("\\")
            i += 1
            continue
        if c != "$":
            out.append(c)
            i += 1
            continue
        if i + 1 < n and text[i + 1] == "{":
            close = text.find("}", i + 2)
            if close < 0:
                raise DockerfileSyntaxError("Unterminated ${...} expression in value.")
            inner = text[i + 2 : close]
            i = close + 1
            out.append(_expand_braced(inner, env))
        else:
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            if j == i + 1:
                out.append("$")
                i += 1
            else:
                name = text[i + 1 : j]
                out.append(_lookup_or_empty(name, env))
                i = j
    return "".join(out)


_BRACED_OP_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(:[-+?]|[-+?])(.*)$")


def _expand_braced(inner: str, env: dict[str, str | None]) -> str:
    m = _BRACED_OP_RE.match(inner)
    if not m:
        return _lookup_or_empty(inner, env)
    name, op, arg = m.group(1), m.group(2), m.group(3)
    raw = env.get(name)
    if op == ":-":
        return raw if raw else arg
    if op == "-":
        return arg if raw is None else raw
    if op == ":+":
        return arg if raw else ""
    if op == "+":
        return arg if raw is not None else ""
    # ":?" and "?" are bash-isms; we leave them as plain lookups.
    return _lookup_or_empty(name, env)


def _lookup_or_empty(name: str, env: dict[str, str | None]) -> str:
    val = env.get(name)
    return "" if val is None else str(val)
