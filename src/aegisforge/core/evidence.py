"""Evidence records with chain-of-custody tracking.

Evidence is treated as read-only: records describe what was collected,
when, from where, and by whom, and every handling step is appended to
the custody log. Later forensic phases build on this model.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso


@dataclass
class CustodyEntry:
    timestamp: str
    actor: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    """One piece of collected evidence."""

    kind: str
    source: str
    description: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    sha256: str | None = None
    collected_by: str = "aegisforge"
    evidence_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    collected_at: str = field(default_factory=utc_now_iso)
    custody: list[CustodyEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("kind must not be empty")
        if not self.source:
            raise ValueError("source must not be empty")

    def add_custody(self, actor: str, action: str) -> None:
        self.custody.append(
            CustodyEntry(timestamp=utc_now_iso(), actor=actor, action=action)
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @staticmethod
    def hash_bytes(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
