"""Normalized log event model.

Every parser emits :class:`LogEvent` — one parsed line with a UTC
ISO-8601 timestamp (when the format carries one), a normalized
severity, and the raw line kept for evidence. Lines a parser cannot
understand become :class:`ParseWarning` instead of raising: malformed
input is reported with a line number, never crashes the parse.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.findings import SEVERITIES

# Parser names used across detect/analyze/CLI.
PARSER_SYSLOG = "syslog"
PARSER_APACHE = "apache"
PARSER_JSON = "json"
PARSER_WINEVENT = "winevent"
PARSER_KEYVALUE = "keyvalue"
PARSER_UNKNOWN = "unknown"

PARSERS = (
    PARSER_SYSLOG,
    PARSER_APACHE,
    PARSER_JSON,
    PARSER_WINEVENT,
    PARSER_KEYVALUE,
)

#: Hard cap on raw-line bytes kept per event (evidence stays small).
MAX_RAW_LEN = 2000


@dataclass
class LogEvent:
    """One normalized log line."""

    message: str
    timestamp: str | None = None  # UTC ISO-8601, None when the format has none
    parser: str = PARSER_UNKNOWN
    host: str | None = None
    severity: str = "info"
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    line_number: int = 0

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if len(self.raw) > MAX_RAW_LEN:
            self.raw = self.raw[:MAX_RAW_LEN] + "…"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParseWarning:
    """A line the parser could not understand (reported, not raised)."""

    line_number: int
    reason: str
    excerpt: str = ""

    def __post_init__(self) -> None:
        if len(self.excerpt) > 200:
            self.excerpt = self.excerpt[:200] + "…"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
