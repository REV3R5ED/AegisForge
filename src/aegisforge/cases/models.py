"""Case data models for the v0.6 incident-response engine.

A case is a working folder with metadata, attached evidence, tracked
findings, linked indicators and analyst notes. Everything is stored as
plain JSON so a case directory is self-describing and tool-agnostic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.logging import utc_now_iso

CASE_STATUSES = ("open", "in-progress", "closed")

FINDING_STATUSES = ("open", "investigating", "resolved", "false-positive")

#: Allowed finding status transitions.
FINDING_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("investigating", "resolved", "false-positive"),
    "investigating": ("resolved", "false-positive", "open"),
    "resolved": ("open",),
    "false-positive": ("open",),
}

EVIDENCE_KINDS = ("network", "logs", "files")

INDICATOR_TYPES = ("ip", "domain", "hash", "url", "email")


@dataclass
class AnalystNote:
    """One append-only analyst note with a UTC timestamp."""

    text: str
    created: str = field(default_factory=utc_now_iso)
    author: str = "analyst"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalystNote:
        return cls(
            text=data["text"],
            created=data.get("created", utc_now_iso()),
            author=data.get("author", "analyst"),
        )


@dataclass
class EvidenceRecord:
    """One file attached to a case (copied, never moved)."""

    evidence_id: str
    kind: str
    original_path: str
    stored_path: str  # relative to the case directory
    sha256: str
    size: int
    attached_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        return cls(**data)


@dataclass
class IndicatorLink:
    """An indicator string linked to a finding.

    ``type_source`` is ``"guessed"`` when AegisForge inferred the type
    from the value's shape and ``"specified"`` when the analyst chose
    it with ``--type``.
    """

    value: str
    type: str
    type_source: str = "guessed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IndicatorLink:
        return cls(**data)


@dataclass
class CaseFinding:
    """A finding tracked inside a case, with lifecycle status."""

    finding_id: str
    title: str
    severity: str
    confidence: int
    detail: str
    status: str = "open"
    indicators: list[IndicatorLink] = field(default_factory=list)
    created: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["indicators"] = [i.to_dict() for i in self.indicators]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CaseFinding:
        indicators = [IndicatorLink.from_dict(i) for i in data.get("indicators", [])]
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            severity=data["severity"],
            confidence=data["confidence"],
            detail=data.get("detail", ""),
            status=data.get("status", "open"),
            indicators=indicators,
            created=data.get("created", utc_now_iso()),
        )


@dataclass
class CaseMetadata:
    """The whole case: metadata, notes, evidence and findings."""

    case_id: str
    title: str
    created: str = field(default_factory=utc_now_iso)
    status: str = "open"
    notes: list[AnalystNote] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    findings: list[CaseFinding] = field(default_factory=list)
    finding_seq: int = 0
    evidence_seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "created": self.created,
            "status": self.status,
            "notes": [n.to_dict() for n in self.notes],
            "evidence": [e.to_dict() for e in self.evidence],
            "findings": [f.to_dict() for f in self.findings],
            "finding_seq": self.finding_seq,
            "evidence_seq": self.evidence_seq,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CaseMetadata:
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            created=data.get("created", utc_now_iso()),
            status=data.get("status", "open"),
            notes=[AnalystNote.from_dict(n) for n in data.get("notes", [])],
            evidence=[EvidenceRecord.from_dict(e) for e in data.get("evidence", [])],
            findings=[CaseFinding.from_dict(f) for f in data.get("findings", [])],
            finding_seq=data.get("finding_seq", 0),
            evidence_seq=data.get("evidence_seq", 0),
        )

    def get_finding(self, finding_id: str) -> CaseFinding | None:
        for finding in self.findings:
            if finding.finding_id == finding_id:
                return finding
        return None


@dataclass
class TimelineEntry:
    """One entry in a case's unified timeline.

    ``timestamp`` is UTC ISO-8601 or None for untimed entries (which
    are listed in a separate section, never dropped silently).
    """

    timestamp: str | None
    source: str  # e.g. "logs:auth.log", "files:report.pdf", "network:scan.json"
    kind: str  # e.g. "log-event", "file-mtime", "network-event", "evidence-attached"
    summary: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
