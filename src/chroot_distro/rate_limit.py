"""Token-bucket bandwidth limiter (PyLoad §5 algorithm).

A single :class:`TokenBucket` is shared across all download threads so
that the *aggregate* throughput is capped at the configured rate — each
individual thread does not need its own bucket.

Setting *rate* to ``0`` disables throttling entirely (no-op).
"""

import threading
import time


class TokenBucket:
    """Shared token-bucket rate limiter.

    Parameters
    ----------
    rate:
        Maximum bytes per second.  ``0`` means unlimited.
    """

    __slots__ = ("_last", "_lock", "_rate", "_tokens")

    def __init__(self, rate: int) -> None:
        self._rate = rate
        self._tokens: float = 0.0
        self._last: float = time.monotonic()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    @property
    def rate(self) -> int:
        """Configured rate in bytes/sec (0 = unlimited)."""
        return self._rate

    # ------------------------------------------------------------------
    def consume(self, nbytes: int) -> None:
        """Charge *nbytes* against the bucket, sleeping if over-budget.

        Algorithm (from PyLoad §5):

        1. Accumulate tokens proportional to elapsed time since last call.
        2. Subtract *nbytes* from the bucket.
        3. If the bucket goes negative we are downloading faster than the
           configured rate — sleep for ``abs(tokens) / rate`` seconds.
           The pause lets the TCP receive window fill, causing the sender
           to slow down automatically.
        """
        if self._rate <= 0:
            return

        sleep_duration = 0.0
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            self._tokens = min(
                float(self._rate),
                self._tokens + self._rate * delta,
            )
            self._last = now
            self._tokens -= nbytes
            if self._tokens < 0:
                sleep_duration = abs(self._tokens) / self._rate

        if sleep_duration > 0:
            time.sleep(sleep_duration)
