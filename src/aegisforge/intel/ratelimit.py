"""Per-provider token-bucket rate limiter.

Each provider gets a bucket refilling at ``rate_per_second`` tokens up
to ``capacity``. A lookup consumes one token; when the bucket is empty
the lookup is *skipped* with a clear message — the tool never hammers a
provider, it just reports that the budget is spent.
"""

from __future__ import annotations

import time


class RateLimiter:
    """Token bucket keyed by provider name."""

    def __init__(
        self, rate_per_second: float = 5.0, capacity: int | None = None
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = float(rate_per_second)
        self.capacity = (
            capacity if capacity is not None else max(1, int(rate_per_second))
        )
        self._tokens: dict[str, float] = {}
        self._updated: dict[str, float] = {}

    def _refill(self, key: str, now: float) -> float:
        tokens = self._tokens.get(key, float(self.capacity))
        last = self._updated.get(key, now)
        tokens = min(float(self.capacity), tokens + (now - last) * self.rate)
        self._tokens[key] = tokens
        self._updated[key] = now
        return tokens

    def acquire(self, key: str) -> bool:
        """Take one token for *key*; True when allowed, False when spent."""
        now = time.monotonic()
        tokens = self._refill(key, now)
        if tokens >= 1.0:
            self._tokens[key] = tokens - 1.0
            return True
        return False

    def retry_after(self, key: str) -> float:
        """Seconds until one token is available for *key*."""
        now = time.monotonic()
        tokens = self._refill(key, now)
        if tokens >= 1.0:
            return 0.0
        return (1.0 - tokens) / self.rate
