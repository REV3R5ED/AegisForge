"""Finding model: an analyst-facing conclusion backed by evidence.

A finding always distinguishes what was *observed* from what was
*inferred*: ``evidence`` lists the observations, ``reason`` explains the
inference in plain language, and ``confidence`` scores it 0-100.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """One finding produced by analysis of evidence."""

    title: str
    severity: str = "info"
    confidence: int = 50
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if not 0 <= self.confidence <= 100:
            raise ValueError(f"confidence must be 0-100, got {self.confidence!r}")
        if not self.title:
            raise ValueError("title must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
