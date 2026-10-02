"""Normalized event model shared by every AegisForge module.

All timestamps are UTC ISO-8601. The event model is what later phases
(log parsers, PCAP analysis, correlation) normalize into — network
discovery in v0.1 emits events for completed observations so the
pipeline shape is exercised from day one.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Event:
    """One normalized observation."""

    event_type: str
    source: str
    severity: str = "info"
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if not self.event_type:
            raise ValueError("event_type must not be empty")
        if not self.source:
            raise ValueError("source must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
