"""Correlation orchestration: extract, graph, enrich, score.

:func:`correlate_case` is the single entry point. It is read-only over
the case: evidence files are opened for reading only and the case store
is never written. Intel enrichment is optional and injected as a
callable so the package stays decoupled from provider configuration —
the CLI wires the real intel engine, tests inject fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aegisforge.cases.models import CaseMetadata
from aegisforge.correlate import extract as extract_mod
from aegisforge.correlate.graph import build_graph
from aegisforge.correlate.models import CorrelationResult, Entity
from aegisforge.correlate.scoring import detect_pivots
from aegisforge.intel.models import INDICATOR_TYPES, NormalizedIndicator

#: Verdict strength for scoring (strongest signal wins).
_VERDICT_RANK = {
    "malicious": 4,
    "suspicious": 3,
    "clean": 2,
    "unknown": 1,
    "no-verdict": 0,
}

_SIGNAL_VERDICTS = ("malicious", "suspicious", "clean")


def to_normalized_indicator(entity: Entity) -> NormalizedIndicator | None:
    """Map a pivot entity to an intel indicator; None when unmappable."""
    if entity.type not in INDICATOR_TYPES:
        return None  # user/hostname are not intel indicator types
    kwargs: dict[str, Any] = {"value": entity.value, "type": entity.type}
    if entity.type == "url":
        kwargs["url"] = entity.value
    return NormalizedIndicator(original=entity.value, **kwargs)


def verdict_maps(
    records: list[Any],
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    """Per-entity (score verdict, display verdict) from intel records.

    The score verdict is the strongest signal seen (malicious wins);
    the display verdict is ``"conflicting"`` when providers disagree on
    signal verdicts, otherwise the strongest verdict.
    """
    by_entity: dict[tuple[str, str], list[str]] = {}
    for record in records:
        if getattr(record, "skipped", False):
            continue
        key = (record.indicator_type, record.indicator)
        by_entity.setdefault(key, []).append(record.verdict)
    score_verdicts: dict[tuple[str, str], str] = {}
    display_verdicts: dict[tuple[str, str], str] = {}
    for key, verdicts in by_entity.items():
        ranked = sorted(verdicts, key=lambda v: _VERDICT_RANK.get(v, 0))
        best = ranked[-1]
        score_verdicts[key] = best
        signals = {v for v in verdicts if v in _SIGNAL_VERDICTS}
        display_verdicts[key] = "conflicting" if len(signals) > 1 else best
    return score_verdicts, display_verdicts


def correlate_case(
    case: CaseMetadata,
    window_seconds: int = 3600,
    min_sources: int = 2,
    intel_lookup: Callable[[list[NormalizedIndicator]], Any] | None = None,
) -> CorrelationResult:
    """Correlate one case's evidence into entities, pivots and edges.

    ``intel_lookup`` optionally enriches pivot entities (receives the
    mappable indicators, returns an object with a ``records`` list of
    intel records). Read-only: never writes the case store or evidence.
    """
    observations, edges, warnings = extract_mod.extract_observations(case)
    graph = build_graph(observations, edges)

    score_verdicts: dict[tuple[str, str], str] = {}
    enriched = False
    if intel_lookup is not None:
        candidates = [
            entity
            for entity in graph.entities()
            if len(graph.source_types_of(entity)) >= min_sources
        ]
        indicators = [
            ind
            for entity in candidates
            if (ind := to_normalized_indicator(entity)) is not None
        ]
        if indicators:
            enrichment = intel_lookup(indicators)
            score_verdicts, display_verdicts = verdict_maps(
                getattr(enrichment, "records", [])
            )
            enriched = True
        else:
            display_verdicts = {}
    else:
        display_verdicts = {}

    pivots = detect_pivots(
        graph,
        min_sources=min_sources,
        window_seconds=window_seconds,
        verdicts=score_verdicts,
    )
    for pivot in pivots:
        if pivot.entity.key() in display_verdicts:
            pivot.verdict = display_verdicts[pivot.entity.key()]

    return CorrelationResult(
        case_id=case.case_id,
        entities=graph.entities(),
        entity_source_counts=graph.source_counts(),
        pivots=pivots,
        edges=graph.edges(),
        window_seconds=window_seconds,
        min_sources=min_sources,
        enriched=enriched,
        warnings=warnings,
    )
