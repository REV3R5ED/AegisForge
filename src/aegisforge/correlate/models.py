"""Correlation data models: entities, observations, edges, pivots, results.

An *entity* is a normalized thing (IP, domain, URL, hash, user, hostname).
An *observation* records one sighting of an entity: where it was seen
(evidence ref), in which source type, and when (UTC ISO-8601 or None).
A *pivot* is an entity observed in ``min_sources`` or more distinct
source types — a cross-source match. Every pivot and every edge carries
its evidence references; a pivot with no evidence is impossible by
construction and rejected in :meth:`Pivot.__post_init__`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

ENTITY_TYPES = ("ip", "domain", "url", "hash", "user", "hostname")

#: Source types that can contribute observations to the entity graph.
SOURCE_TYPES = ("logs", "network", "files", "findings")


@dataclass
class Entity:
    """One normalized entity: canonical ``value`` plus its ``type``."""

    value: str
    type: str

    def __post_init__(self) -> None:
        if self.type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type must be one of {ENTITY_TYPES}, got {self.type!r}"
            )
        if not self.value:
            raise ValueError("entity value must not be empty")

    def key(self) -> tuple[str, str]:
        """Identity key: (type, value)."""
        return (self.type, self.value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    """One sighting of an entity in case evidence.

    ``source_type`` is one of :data:`SOURCE_TYPES`; ``source_label``
    names the concrete evidence (``logs:auth.log``); ``evidence_id``
    is the case evidence ID; ``timestamp`` is UTC ISO-8601 or None
    when the sighting could not be placed in time.
    """

    entity: Entity
    source_type: str
    source_label: str
    evidence_id: str
    timestamp: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(
                f"source type must be one of {SOURCE_TYPES}, got {self.source_type!r}"
            )
        if not self.evidence_id:
            raise ValueError("observation must carry an evidence_id")

    def evidence_ref(self) -> str:
        return f"{self.source_label} [{self.evidence_id}]"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["entity"] = self.entity.to_dict()
        return d


@dataclass
class Edge:
    """Two entities observed together (same log line, same flow, ...).

    ``relation`` is always ``"observed-together"`` — co-occurrence, never
    causation. ``evidence_refs`` is non-empty by construction.
    """

    entity_a: Entity
    entity_b: Entity
    relation: str = "observed-together"
    evidence_refs: list[str] = field(default_factory=list)
    timestamps: list[str | None] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise ValueError("an edge must carry at least one evidence ref")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["entity_a"] = self.entity_a.to_dict()
        d["entity_b"] = self.entity_b.to_dict()
        return d


@dataclass
class ScoreComponent:
    """One transparent term of a pivot's confidence score."""

    points: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Pivot:
    """A cross-source match: one entity seen in several source types.

    ``score`` is transparent arithmetic (see
    :mod:`aegisforge.correlate.scoring`); ``components`` shows the math.
    ``verdict`` is the best intel verdict seen for the entity, or None
    when no enrichment ran. ``temporal_links`` names observation pairs
    from different sources seen within the correlation window.
    """

    entity: Entity
    source_types: list[str]
    observations: list[Observation] = field(default_factory=list)
    score: int = 0
    components: list[ScoreComponent] = field(default_factory=list)
    verdict: str | None = None
    temporal_links: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.observations:
            raise ValueError("a pivot must carry at least one observation")
        if not 0 <= self.score <= 100:
            raise ValueError(f"pivot score must be 0-100, got {self.score!r}")

    def evidence_refs(self) -> list[str]:
        refs: list[str] = []
        for obs in self.observations:
            ref = obs.evidence_ref()
            if ref not in refs:
                refs.append(ref)
        return refs

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity.to_dict(),
            "source_types": self.source_types,
            "source_count": len(self.source_types),
            "observation_count": len(self.observations),
            "score": self.score,
            "components": [c.to_dict() for c in self.components],
            "verdict": self.verdict,
            "temporal_links": self.temporal_links,
            "evidence_refs": self.evidence_refs(),
        }


@dataclass
class CorrelationResult:
    """The full outcome of correlating one case."""

    case_id: str
    entities: list[Entity] = field(default_factory=list)
    entity_source_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    pivots: list[Pivot] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    window_seconds: int = 3600
    min_sources: int = 2
    enriched: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "entity_count": len(self.entities),
            "pivot_count": len(self.pivots),
            "edge_count": len(self.edges),
            "window_seconds": self.window_seconds,
            "min_sources": self.min_sources,
            "enriched": self.enriched,
            "entities": [e.to_dict() for e in self.entities],
            "entity_source_counts": self.entity_source_counts,
            "pivots": [p.to_dict() for p in self.pivots],
            "edges": [e.to_dict() for e in self.edges],
            "warnings": self.warnings,
        }
