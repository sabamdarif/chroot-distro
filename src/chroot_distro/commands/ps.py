"""``chroot-distro ps`` — list active container sessions.

Lists active sessions reported by the session registry
(:mod:`chroot_distro.helpers.session_registry`).  ``active_sessions()``
already prunes dead entries, so this module only formats output.
``--quiet`` prints one PID per line (to stdout, for piping into
``kill``/``xargs``); the default renders a coloured
PID/CONTAINER/TYPE/USER/UPTIME/COMMAND table to stderr, mirroring the
style of ``command_list``.
"""

from __future__ import annotations

import os
import shlex
import time

from chroot_distro.constants import PROGRAM_NAME
from chroot_distro.helpers.session_registry import active_sessions
from chroot_distro.message import C, msg

# Fixed columns (everything except the trailing, space-filling COMMAND).
_HEADERS = ("PID", "CONTAINER", "TYPE", "USER", "UPTIME", "COMMAND")
_GAP = 2


def command_ps(args) -> None:
    """List every active container session (one row per live session)."""
    quiet = getattr(args, "quiet", False)
    sessions = active_sessions()

    if quiet:
        for sess in sessions:
            print(sess.get("pid", ""))
        return

    msg()
    if not sessions:
        msg(f"{C['YELLOW']}No active sessions.{C['RST']}")
        msg()
        msg(
            f"{C['CYAN']}Start one with: "
            f"{C['GREEN']}{PROGRAM_NAME} login <name>{C['RST']}"
        )
        msg()
        return

    now = time.time()
    rows = []
    has_detached = False
    for sess in sessions:
        kind = str(sess.get("kind", "?"))
        if sess.get("detached", False):
            kind = f"{kind}*"
            has_detached = True
        rows.append((
            str(sess.get("pid", "?")),
            str(sess.get("container", "?")),
            kind,
            str(sess.get("user", "?")),
            _fmt_uptime(now - sess.get("start_time", now)),
            _fmt_command(sess.get("command")),
        ))

    # Fixed-column widths are content-driven; COMMAND takes the rest of
    # the terminal width and is truncated if it overflows.
    widths = [
        max(len(_HEADERS[i]), *(len(r[i]) for r in rows))
        for i in range(len(_HEADERS) - 1)
    ]
    used = sum(widths) + _GAP * len(widths)
    cmd_width = max(len(_HEADERS[-1]), _table_width() - used)

    pad = " " * _GAP
    head = [_HEADERS[i].ljust(widths[i]) for i in range(len(widths))]
    head.append(_HEADERS[-1])
    msg(f"{C['UBCYAN']}{pad.join(head)}{C['RST']}")

    for r in rows:
        cmd = r[-1]
        if len(cmd) > cmd_width:
            cmd = cmd[: max(1, cmd_width - 1)] + "…"
        cells = [
            f"{C['CYAN']}{r[0].ljust(widths[0])}{C['RST']}",
            f"{C['GREEN']}{r[1].ljust(widths[1])}{C['RST']}",
            f"{C['CYAN']}{r[2].ljust(widths[2])}{C['RST']}",
            f"{C['CYAN']}{r[3].ljust(widths[3])}{C['RST']}",
            f"{C['CYAN']}{r[4].ljust(widths[4])}{C['RST']}",
            f"{C['CYAN']}{cmd}{C['RST']}",
        ]
        msg(pad.join(cells))

    msg()
    if has_detached:
        msg(f"{C['CYAN']}* detached session{C['RST']}")
        msg()


def _fmt_uptime(seconds: float) -> str:
    """Compact human-readable elapsed time (e.g. '0m44s', '1h04m', '2d03h')."""
    s = int(seconds) if seconds > 0 else 0
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    return f"{s // 86400}d{(s % 86400) // 3600:02d}h"


def _fmt_command(command) -> str:
    """Render the recorded inner argv as a single shell-style string."""
    if isinstance(command, (list, tuple)):
        parts = [str(c) for c in command]
        try:
            return shlex.join(parts)
        except (TypeError, ValueError):
            return " ".join(parts)
    return str(command or "")


def _table_width() -> int:
    """Actual terminal column count (stderr first), defaulting to 80."""
    for fd in (2, 1):
        try:
            cols = os.get_terminal_size(fd).columns
        except (OSError, ValueError):
            continue
        if cols > 0:
            return cols
    return 80


__all__ = ("command_ps",)
