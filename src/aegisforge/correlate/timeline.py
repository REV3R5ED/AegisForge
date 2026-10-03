"""Incident timeline: case timeline entries merged with pivot events.

The v0.6 case timeline (log events, file mtimes, network evidence) is
merged with one entry per pivot — "pivot: <type>:<value> observed in N
sources" — timestamped at the pivot's earliest observation and flagged
with ``pivot=True`` so renderers can highlight it. Every entry remains
evidence-backed: pivot entries list the pivot's evidence refs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from aegisforge.cases import timeline as case_timeline_mod
from aegisforge.cases.models import CaseMetadata, TimelineEntry
from aegisforge.correlate.models import Pivot
from aegisforge.correlate.scoring import _parse_ts


@dataclass
class IncidentTimelineEntry:
    """One entry of the incident timeline."""

    timestamp: str | None
    source: str
    kind: str
    summary: str
    detail: str = ""
    pivot: bool = False
    pivot_score: int | None = None
    evidence_refs: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _pivot_entry(pivot: Pivot) -> IncidentTimelineEntry:
    earliest: str | None = None
    earliest_dt = None
    for obs in pivot.observations:
        ts = _parse_ts(obs.timestamp)
        if ts is not None and (earliest_dt is None or ts < earliest_dt):
            earliest_dt = ts
            earliest = obs.timestamp
    entity = pivot.entity
    return IncidentTimelineEntry(
        timestamp=earliest,
        source="correlation",
        kind="pivot",
        summary=(
            f">>> pivot: {entity.type}:{entity.value} observed in "
            f"{len(pivot.source_types)} sources "
            f"({', '.join(pivot.source_types)}) — score {pivot.score}"
        ),
        detail="; ".join(c.reason for c in pivot.components),
        pivot=True,
        pivot_score=pivot.score,
        evidence_refs=pivot.evidence_refs(),
    )


def build_incident_timeline(
    case: CaseMetadata, pivots: list[Pivot]
) -> tuple[list[IncidentTimelineEntry], list[IncidentTimelineEntry]]:
    """Merge the case timeline with pivot events.

    Returns ``(timed, untimed)``: timed entries are chronological,
    untimed entries carry ``timestamp=None`` and are listed separately —
    never dropped.
    """
    timed_raw, untimed_raw = case_timeline_mod.build_case_timeline(case)
    timed: list[IncidentTimelineEntry] = [
        IncidentTimelineEntry(
            timestamp=e.timestamp,
            source=e.source,
            kind=e.kind,
            summary=e.summary,
            detail=e.detail,
        )
        for e in timed_raw
    ]
    untimed: list[IncidentTimelineEntry] = [
        IncidentTimelineEntry(
            timestamp=None,
            source=e.source,
            kind=e.kind,
            summary=e.summary,
            detail=e.detail,
        )
        for e in untimed_raw
    ]
    for pivot in pivots:
        entry = _pivot_entry(pivot)
        (timed if entry.timestamp else untimed).append(entry)
    # UTC ISO-8601 strings sort chronologically as plain strings.
    timed.sort(
        key=lambda e: (
            e.timestamp or "",
            0 if e.pivot else 1,  # pivot entries first on timestamp ties
            e.source,
            e.summary,
        )
    )
    return timed, untimed


def incident_timeline_to_dict(
    timed: list[IncidentTimelineEntry], untimed: list[IncidentTimelineEntry]
) -> dict[str, Any]:
    return {
        "timed": [e.to_dict() for e in timed],
        "untimed": [e.to_dict() for e in untimed],
        "timed_count": len(timed),
        "untimed_count": len(untimed),
        "pivot_count": sum(1 for e in timed + untimed if e.pivot),
        "note": "Pivot entries mark entities observed in multiple sources. "
        "Temporal proximity is observation, not causation. Untimed events "
        "could not be placed chronologically and are listed separately, "
        "never dropped.",
        "entry_model": TimelineEntry.__name__,
    }
