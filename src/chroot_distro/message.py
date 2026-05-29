import os
import sys
from typing import Any

termios: Any
try:
    import termios
except ImportError:
    termios = None


_RST       = "\033[0m"
_BOLD      = "\033[1m"
_ITALIC    = "\033[3m"
_UNDERLINE = "\033[4m"
_RED       = "\033[31m"
_GREEN     = "\033[32m"
_YELLOW    = "\033[33m"
_BLUE      = "\033[34m"
_MAGENTA   = "\033[35m"
_CYAN      = "\033[36m"
_WHITE     = "\033[37m"

_COLORS = {
    "RST":     _RST,

    "RED": _RST + _RED,
    "BRED": _RST + _BOLD + _RED,
    "IRED": _RST + _ITALIC + _RED,
    "URED": _RST + _UNDERLINE + _RED,
    "UBRED": _RST + _UNDERLINE + _BOLD + _RED,

    "GREEN": _RST + _GREEN,
    "BGREEN": _RST + _BOLD + _GREEN,
    "IGREEN": _RST + _ITALIC + _GREEN,
    "UGREEN": _RST + _UNDERLINE + _GREEN,
    "UBGREEN": _RST + _UNDERLINE + _BOLD + _GREEN,

    "YELLOW": _RST + _YELLOW,
    "BYELLOW": _RST + _BOLD + _YELLOW,
    "IYELLOW": _RST + _ITALIC + _YELLOW,
    "UYELLOW": _RST + _UNDERLINE + _YELLOW,
    "UBYELLOW": _RST + _UNDERLINE + _BOLD + _YELLOW,

    "BLUE": _RST + _BLUE,
    "BBLUE": _RST + _BOLD + _BLUE,
    "IBLUE": _RST + _ITALIC + _BLUE,
    "UBLUE": _RST + _UNDERLINE + _BLUE,
    "UBBLUE": _RST + _UNDERLINE + _BOLD + _BLUE,

    "MAGENTA": _RST + _MAGENTA,
    "BMAGENTA": _RST + _BOLD + _MAGENTA,
    "IMAGENTA": _RST + _ITALIC + _MAGENTA,
    "UMAGENTA": _RST + _UNDERLINE + _MAGENTA,
    "UBMAGENTA": _RST + _UNDERLINE + _BOLD + _MAGENTA,

    "CYAN": _RST + _CYAN,
    "BCYAN": _RST + _BOLD + _CYAN,
    "ICYAN": _RST + _ITALIC + _CYAN,
    "UCYAN": _RST + _UNDERLINE + _CYAN,
    "UBCYAN": _RST + _UNDERLINE + _BOLD + _CYAN,

    "WHITE": _RST + _WHITE,
    "BWHITE": _RST + _BOLD + _WHITE,
    "IWHITE": _RST + _ITALIC + _WHITE,
    "UWHITE": _RST + _UNDERLINE + _WHITE,
    "UBWHITE": _RST + _UNDERLINE + _BOLD + _WHITE,
}
_EMPTY = dict.fromkeys(_COLORS, "")


def _init_colors() -> dict:
    if sys.stderr.isatty() and not os.environ.get("CD_FORCE_NO_COLORS"):
        return _COLORS
    return _EMPTY


C = _init_colors()


def tty_safe_for_writes() -> bool:
    """Return False when stderr's TTY is currently being used by another
    process for interactive input (a password prompt or a full-screen
    curses UI). Return True otherwise.
    """
    if termios is None:
        return True
    try:
        fd = sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):
        return True
    try:
        if not os.isatty(fd):
            return True
    except OSError:
        return True
    try:
        attrs = termios.tcgetattr(fd)
    except (OSError, termios.error):
        return True
    lflag = attrs[3]
    return bool(lflag & termios.ECHO) and bool(lflag & termios.ICANON)


_quiet = False


def set_quiet(value: bool) -> None:
    """Enable or disable quiet mode for the rest of the process."""
    global _quiet  # noqa: PLW0603
    _quiet = bool(value)



def is_quiet() -> bool:
    """Return True when quiet mode has been enabled for this process."""
    return _quiet


def msg(*args):
    """Print *args* to stderr after clearing any partial progress line."""
    if not tty_safe_for_writes():
        return
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()
    print(*args, file=sys.stderr)


def log_info(text: str):
    """Emit a `[*] text` info line. No-op under --quiet."""
    if _quiet:
        return
    msg(f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}{text}{C['RST']}")


def log_error(text: str):
    """Emit a `[!] text` error line. Always shown — even under --quiet."""
    msg(f"{C['BLUE']}[{C['RED']}!{C['BLUE']}] {C['CYAN']}{text}{C['RST']}")


def warn(text: str):
    """Emit a 'Warning: text' line in yellow."""
    msg(f"{C['BYELLOW']}Warning: {C['YELLOW']}{text}{C['RST']}")


def crit_error(text: str):
    """Emit an 'Error: text' line in red."""
    msg(f"{C['BRED']}Error: {C['RED']}{text}{C['RST']}")
