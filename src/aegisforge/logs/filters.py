"""Composable event filters for log analysis.

All filters are AND-combined: an event must satisfy every active
criterion. Time bounds accept ISO-8601 (a trailing ``Z`` is fine);
naive datetimes are assumed UTC.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegisforge.logs.models import LogEvent
from aegisforge.logs.parsers import parse_iso_timestamp


def _as_utc(text: str) -> datetime | None:
    iso = parse_iso_timestamp(text)
    if iso is None:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


@dataclass
class LogFilter:
    """Filter criteria for :func:`matches`. All active filters must pass."""

    since: str | None = None
    until: str | None = None
    levels: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()
    not_contains: tuple[str, ...] = ()
    host: str | None = None
    limit: int | None = None

    # Resolved bounds (populated by `resolve()`).
    _since_dt: datetime | None = field(default=None, init=False, repr=False)
    _until_dt: datetime | None = field(default=None, init=False, repr=False)

    def resolve(self) -> LogFilter:
        """Parse time bounds once; raises ValueError on bad input."""
        if self.since is not None:
            parsed = _as_utc(self.since)
            if parsed is None:
                raise ValueError(f"--since is not a valid timestamp: {self.since!r}")
            self._since_dt = parsed
        if self.until is not None:
            parsed = _as_utc(self.until)
            if parsed is None:
                raise ValueError(f"--until is not a valid timestamp: {self.until!r}")
            self._until_dt = parsed
        return self

    def _event_time(self, event: LogEvent) -> datetime | None:
        if event.timestamp is None:
            return None
        try:
            return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None

    def matches(self, event: LogEvent) -> bool:
        if self.levels and event.severity not in self.levels:
            return False
        if self.host is not None and (event.host or "").lower() != self.host.lower():
            return False
        haystack = f"{event.message}\n{event.raw}".lower()
        for needle in self.contains:
            if needle.lower() not in haystack:
                return False
        for needle in self.not_contains:
            if needle.lower() in haystack:
                return False
        if self._since_dt is not None or self._until_dt is not None:
            moment = self._event_time(event)
            if moment is None:
                return False
            if self._since_dt is not None and moment < self._since_dt:
                return False
            if self._until_dt is not None and moment > self._until_dt:
                return False
        return True

    def describe(self) -> dict[str, object]:
        """Active criteria, for the result envelope."""
        desc: dict[str, object] = {}
        if self.since:
            desc["since"] = self.since
        if self.until:
            desc["until"] = self.until
        if self.levels:
            desc["levels"] = list(self.levels)
        if self.contains:
            desc["contains"] = list(self.contains)
        if self.not_contains:
            desc["not_contains"] = list(self.not_contains)
        if self.host:
            desc["host"] = self.host
        if self.limit is not None:
            desc["limit"] = self.limit
        return desc
