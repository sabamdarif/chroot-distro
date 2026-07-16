"""Build output events and reporters.

The engine emits :class:`BuildEvent` records; a reporter renders them.
Three renderers: plain one-line-per-event (today's format), a minimal
TTY renderer that collapses finished steps, and JSON-lines for tooling.
Selected via ``--progress {auto,plain,tty,rawjson}``; ``--quiet`` maps
to the no-op reporter.
"""

import dataclasses
import json
import sys
import typing

from chroot_distro.message import C, log_info, msg

# Event kinds: step_started | step_finished | cache_hit | log_line | error.


@dataclasses.dataclass
class BuildEvent:
    kind: str
    step_no: int = 0
    step_total: int = 0
    stage_name: str = ""
    instruction: str = ""
    text: str = ""
    duration: float | None = None
    lineno: int = 0


class Reporter(typing.Protocol):
    def emit(self, ev: BuildEvent) -> None: ...


def _head(ev: BuildEvent) -> str:
    """`#N [stage] INSTR` prefix shared by the renderers."""
    stage = f" [{ev.stage_name}]" if ev.stage_name else ""
    return f"#{ev.step_no}{stage} {ev.instruction}"


def _truncate(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


class NullReporter:
    """--quiet: swallow everything."""

    def emit(self, ev: BuildEvent) -> None:
        pass


class PlainReporter:
    """One log_info line per event; keeps today's `Step N/M: INSTR …` format."""

    def emit(self, ev: BuildEvent) -> None:
        if ev.kind == "step_started":
            raw = _truncate(ev.text)
            parts = raw.split(None, 1)
            if len(parts) == 2:
                rendered = f"{C['YELLOW']}{parts[0]}{C['RST']} {parts[1]}"
            elif parts:
                rendered = f"{C['YELLOW']}{parts[0]}{C['RST']}"
            else:
                rendered = ""
            stage = f" [{ev.stage_name}]" if ev.stage_name else ""
            log_info(f"Step {ev.step_no}/{ev.step_total}{stage}: {C['RST']}{rendered}")
        elif ev.kind == "cache_hit":
            log_info(f"{C['GREEN']}CACHED{C['RST']}")
        elif ev.kind == "step_finished":
            # ponytail: sub-0.1s steps (ENV, LABEL, …) skip the done line to
            # avoid doubling the output; drop the threshold if it misleads.
            if ev.duration is not None and ev.duration >= 0.1:
                log_info(f"--> done ({ev.duration:.1f}s)")
        elif ev.kind in ("log_line", "error"):
            log_info(ev.text)


class TTYReporter:
    """Minimal redraw: in-flight step stays on the last line, finished steps collapse."""

    def __init__(self, stream: typing.TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._inflight = ""
        self._cached = False

    def _clear(self) -> None:
        self._stream.write("\r\033[K")

    def _final(self, line: str) -> None:
        self._clear()
        self._stream.write(line + "\n")
        self._stream.flush()
        self._inflight = ""

    def emit(self, ev: BuildEvent) -> None:
        if ev.kind == "step_started":
            self._cached = False
            self._inflight = f"{C['CYAN']}{_head(ev)}{C['RST']} {_truncate(ev.text, 80)}"
            self._clear()
            self._stream.write(self._inflight)
            self._stream.flush()
        elif ev.kind == "cache_hit":
            self._cached = True
            self._final(f"{self._inflight} {C['GREEN']}CACHED{C['RST']}")
        elif ev.kind == "step_finished":
            if self._cached:
                self._cached = False
                return
            dur = f" {C['GREEN']}done {ev.duration:.1f}s{C['RST']}" if ev.duration is not None else ""
            self._final(f"{self._inflight}{dur}")
        elif ev.kind in ("log_line", "error"):
            # Print above the in-flight line, then restore it.
            inflight = self._inflight
            self._clear()
            msg(ev.text)
            if inflight:
                self._stream.write(inflight)
                self._stream.flush()
                self._inflight = inflight


class JSONReporter:
    """--progress=rawjson: one JSON object per line on stdout."""

    def __init__(self, stream: typing.TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def emit(self, ev: BuildEvent) -> None:
        self._stream.write(json.dumps(dataclasses.asdict(ev), sort_keys=True) + "\n")
        self._stream.flush()


def make_reporter(progress: str, quiet: bool) -> Reporter:
    """Pick the reporter for --progress/--quiet (auto = TTY-detect on stderr)."""
    if quiet:
        return NullReporter()
    if progress == "rawjson":
        return JSONReporter()
    if progress == "plain":
        return PlainReporter()
    if progress == "tty":
        return TTYReporter()
    # auto: same TTY detection message.py uses for colors.
    if sys.stderr.isatty():
        return TTYReporter()
    return PlainReporter()
