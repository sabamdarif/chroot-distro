import contextlib
import itertools
import sys
import threading
import time
import typing
from collections import deque

from chroot_distro.message import C, is_quiet, tty_safe_for_writes

REDRAW_THRESHOLD_BYTES = 262144


def fmt_size(n_bytes: int) -> str:
    """Return a human-readable size string (B, KiB, MiB, GiB)."""
    if n_bytes >= 1 << 30:
        return f"{n_bytes / (1 << 30):.1f} GiB"
    if n_bytes >= 1 << 20:
        return f"{n_bytes / (1 << 20):.1f} MiB"
    if n_bytes >= 1 << 10:
        return f"{n_bytes / (1 << 10):.1f} KiB"
    return f"{n_bytes} B"


def _fmt_speed(bps: float) -> str:
    """Return a human-readable speed string (B/s, KiB/s, MiB/s, GiB/s)."""
    if bps >= 1 << 30:
        return f"{bps / (1 << 30):.1f} GiB/s"
    if bps >= 1 << 20:
        return f"{bps / (1 << 20):.1f} MiB/s"
    if bps >= 1 << 10:
        return f"{bps / (1 << 10):.1f} KiB/s"
    return f"{bps:.0f} B/s"


class ByteCounter:
    """File wrapper that tallies bytes flowing through read()/readinto()."""

    def __init__(self, fh):
        self._fh = fh
        self.count = 0

    def read(self, size=-1):
        data = self._fh.read(size)
        self.count += len(data)
        return data

    def readinto(self, buf):
        n = self._fh.readinto(buf)
        self.count += n
        return n

    def __getattr__(self, name):
        return getattr(self._fh, name)


_last_non_tty_pct: dict[tuple[str, str], int] = {}
_last_non_tty_bytes: dict[tuple[str, str], int] = {}


def progress_active() -> bool:
    """Return True when progress output should be written to stderr."""
    return not is_quiet()


def draw_bytes_bar(
    done: int,
    total: int = 0,
    *,
    label: str = "",
    noun: str = "processed",
    speed: float = 0.0,
) -> None:
    """Draw a [####----] progress line keyed by byte counts."""
    if not progress_active() or not tty_safe_for_writes():
        return
    pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"
    head = f"{label}: " if label else ""
    speed_str = f"  {_fmt_speed(speed)}" if speed > 0 else ""
    if sys.stderr.isatty():
        if total:
            pct = min(done * 100 // total, 100)
            bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
            line = f"\r{pfx}{head}[{bar}] {pct:3d}%  {fmt_size(done)} / {fmt_size(total)}{speed_str}\033[K{C['RST']}"
        else:
            line = f"\r{pfx}{head}{fmt_size(done)} {noun}...{speed_str}\033[K{C['RST']}"
        sys.stderr.write(line)
        sys.stderr.flush()
    else:
        key = (label, noun)
        if total:
            pct = min(done * 100 // total, 100)
            last_pct = _last_non_tty_pct.get(key)
            if last_pct is None or done == 0 or done == total or (pct - last_pct) >= 10:
                _last_non_tty_pct[key] = pct
                line = f"{pfx}{head}{noun.capitalize()} {fmt_size(done)} / {fmt_size(total)}{C['RST']}\n"
                sys.stderr.write(line)
                sys.stderr.flush()
            if done == total:
                _last_non_tty_pct.pop(key, None)
        else:
            last_bytes = _last_non_tty_bytes.get(key)
            if last_bytes is None or done == 0 or (done - last_bytes) >= 10485760:
                _last_non_tty_bytes[key] = done
                line = f"{pfx}{head}{noun.capitalize()} {fmt_size(done)}{C['RST']}\n"
                sys.stderr.write(line)
                sys.stderr.flush()


def draw_count_bar(
    done: int,
    total: int,
    *,
    label: str = "",
    unit: str = "files",
) -> None:
    """Draw a [####----] progress line keyed by item count rather than bytes."""
    if not progress_active() or not tty_safe_for_writes():
        return
    pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"
    head = f"{label}: " if label else ""
    if sys.stderr.isatty():
        pct = (done * 100 // total) if total else 100
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        line = f"\r{pfx}{head}[{bar}] {pct:3d}%  {done} / {total} {unit}\033[K{C['RST']}"
        sys.stderr.write(line)
        sys.stderr.flush()
    else:
        key = (label, unit)
        pct = (done * 100 // total) if total else 100
        last_pct = _last_non_tty_pct.get(key)
        if last_pct is None or done == 0 or done == total or (pct - last_pct) >= 10:
            _last_non_tty_pct[key] = pct
            line = f"{pfx}{head}Processed {done} / {total} {unit}{C['RST']}\n"
            sys.stderr.write(line)
            sys.stderr.flush()
        if done == total:
            _last_non_tty_pct.pop(key, None)


def clear_bar() -> None:
    """Erase the current progress line. No-op when output is inactive."""
    if not progress_active() or not tty_safe_for_writes():
        return
    if sys.stderr.isatty():
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()


@contextlib.contextmanager
def loading_line(
    initial: str = "Loading...",
) -> typing.Iterator[typing.Callable[[str], None]]:
    """Show an animated status line on stderr until the context exits.

    Yields an ``update(text)`` callable to change the message (for example
    per-container progress during ``list``).
    """
    if not progress_active() or not tty_safe_for_writes():

        def _noop(_text: str) -> None:
            return

        yield _noop
        return

    pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"

    if not sys.stderr.isatty():
        sys.stderr.write(f"{pfx}{initial}{C['RST']}\n")
        sys.stderr.flush()

        last_text = initial

        def _update_non_tty(text: str) -> None:
            nonlocal last_text
            if text != last_text:
                sys.stderr.write(f"{pfx}{text}{C['RST']}\n")
                sys.stderr.flush()
                last_text = text

        try:
            yield _update_non_tty
        finally:
            pass
        return

    state = {"text": initial}
    stop = threading.Event()

    def _spin() -> None:
        for frame in itertools.cycle("|/-\\"):
            if stop.wait(0.08):
                break
            line = f"\r{pfx}{frame} {state['text']}\033[K{C['RST']}"
            sys.stderr.write(line)
            sys.stderr.flush()

    thread = threading.Thread(target=_spin, daemon=True)
    thread.start()

    def _update_tty(text: str) -> None:
        state["text"] = text

    try:
        yield _update_tty
    finally:
        stop.set()
        thread.join(timeout=1.0)
        clear_bar()


# ---------------------------------------------------------------------------
# Sliding-window speed tracker (PyLoad §4.4)
# ---------------------------------------------------------------------------

_SPEED_WINDOW_SECS = 3.0  # sliding window duration for speed calculation


class AggregateByteProgress:
    """Thread-safe byte counter that drives one shared progress bar.

    Tracks download speed via a 3-second sliding window of
    ``(timestamp, cumulative_bytes)`` samples (PyLoad §4.4).
    """

    def __init__(self, total: int = 0, *, label: str = "") -> None:
        self._lock = threading.Lock()
        self._done = 0
        self._total = total
        self._label = label
        self._last_shown = 0
        # Sliding window: deque of (monotonic_time, cumulative_bytes)
        self._samples: deque[tuple[float, int]] = deque()
        self._start_time = time.monotonic()
        # Draw the initial 0% bar immediately so the user sees feedback
        draw_bytes_bar(0, total, label=label, noun="downloaded")

    def add(self, nbytes: int) -> None:
        with self._lock:
            self._done += nbytes
            now = time.monotonic()
            self._samples.append((now, self._done))
            # Trim samples older than the window
            cutoff = now - _SPEED_WINDOW_SECS
            while self._samples and self._samples[0][0] < cutoff:
                self._samples.popleft()
            speed = self._speed_locked()
            if self._done == self._total or self._done - self._last_shown >= REDRAW_THRESHOLD_BYTES:
                self._last_shown = self._done
                draw_bytes_bar(
                    self._done,
                    self._total,
                    label=self._label,
                    noun="downloaded",
                    speed=speed,
                )

    def _speed_locked(self) -> float:
        """Return current speed in bytes/sec from the sliding window.

        Must be called while holding ``self._lock``.
        """
        if len(self._samples) < 2:
            return 0.0
        oldest_t, oldest_b = self._samples[0]
        newest_t, newest_b = self._samples[-1]
        dt = newest_t - oldest_t
        if dt <= 0:
            return 0.0
        return (newest_b - oldest_b) / dt

    def speed(self) -> float:
        """Return current download speed in bytes/sec (thread-safe)."""
        with self._lock:
            return self._speed_locked()

    def clear(self) -> None:
        clear_bar()
