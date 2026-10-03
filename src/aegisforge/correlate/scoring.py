"""Pivot detection, temporal correlation and explainable scoring.

A *pivot* is an entity observed in ``min_sources`` or more distinct
source types. The confidence score is transparent arithmetic — every
point is accounted for in the pivot's ``components`` list:

- **sources**: 10 points per distinct source type, capped at 40.
  (Two sources = 20, three = 30, four or more = 40.)
- **verdict**: +20 when any intel record for the entity says
  ``malicious``, +10 for ``suspicious``, +0 otherwise (including
  "no enrichment ran", which is stated, not hidden).
- **temporal**: +10 when observations from different sources fall
  within the correlation window of each other.
- **recency**: +10 when the latest observation is within 24 hours of
  now.

The total is capped at 100. The wording is always "observed within X
of each other" — temporal proximity is never presented as causation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegisforge.correlate.graph import EntityGraph
from aegisforge.correlate.models import Entity, Observation, Pivot, ScoreComponent

_MAX_SCORE = 100
_SOURCE_POINTS = 10
_SOURCE_CAP = 40
_VERDICT_POINTS = {"malicious": 20, "suspicious": 10}
_TEMPORAL_POINTS = 10
_RECENCY_POINTS = 10
_RECENCY_WINDOW = timedelta(hours=24)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def format_window(seconds: int) -> str:
    """Human form of a window: 90 -> '1m30s', 3600 -> '1h', 90000 -> '1d1h'."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        minutes, secs = divmod(seconds, 60)
        return f"{minutes}m" + (f"{secs}s" if secs else "")
    if seconds < 86400:
        hours, rem = divmod(seconds, 3600)
        minutes = rem // 60
        return f"{hours}h" + (f"{minutes}m" if minutes else "")
    days, rem = divmod(seconds, 86400)
    hours = rem // 3600
    return f"{days}d" + (f"{hours}h" if hours else "")


def find_temporal_links(
    observations: list[Observation], window_seconds: int
) -> list[str]:
    """Pairs of observations from different sources within the window.

    Returns human-readable link descriptions; empty when fewer than two
    timestamped observations from distinct sources fall in the window.
    """
    timed = [
        (obs, _parse_ts(obs.timestamp))
        for obs in observations
        if _parse_ts(obs.timestamp) is not None
    ]
    links: list[str] = []
    window = format_window(window_seconds)
    for i, (first, first_ts) in enumerate(timed):
        assert first_ts is not None
        for second, second_ts in timed[i + 1 :]:
            assert second_ts is not None
            if first.source_type == second.source_type:
                continue
            delta = abs((first_ts - second_ts).total_seconds())
            if delta <= window_seconds:
                links.append(
                    f"{first.source_label} and {second.source_label} observed "
                    f"within {window} of each other "
                    f"({first.timestamp} / {second.timestamp})"
                )
    return links


def _verdict_points(
    entity: Entity, verdicts: dict[tuple[str, str], str]
) -> tuple[int, str]:
    verdict = verdicts.get(entity.key())
    if verdict is None:
        return 0, "no intel verdict for this entity"
    points = _VERDICT_POINTS.get(verdict, 0)
    if points:
        return points, f"intel verdict '{verdict}' (+{points})"
    return 0, f"intel verdict '{verdict}' carries no pivot weight"


def score_pivot(
    entity: Entity,
    observations: list[Observation],
    source_types: list[str],
    window_seconds: int,
    verdicts: dict[tuple[str, str], str],
    now: datetime | None = None,
) -> tuple[int, list[ScoreComponent], list[str]]:
    """Score one pivot; returns (score, components, temporal_links)."""
    components: list[ScoreComponent] = []

    source_points = min(len(source_types) * _SOURCE_POINTS, _SOURCE_CAP)
    components.append(
        ScoreComponent(
            points=source_points,
            reason=f"{len(source_types)} distinct source types "
            f"({', '.join(source_types)})",
        )
    )

    verdict_points, verdict_reason = _verdict_points(entity, verdicts)
    components.append(ScoreComponent(points=verdict_points, reason=verdict_reason))

    temporal_links = find_temporal_links(observations, window_seconds)
    if temporal_links:
        components.append(
            ScoreComponent(
                points=_TEMPORAL_POINTS,
                reason=(
                    f"{len(temporal_links)} cross-source observation pair(s) "
                    f"within {format_window(window_seconds)}"
                ),
            )
        )
    else:
        components.append(
            ScoreComponent(
                points=0,
                reason=(
                    "no cross-source observations within "
                    f"{format_window(window_seconds)}"
                ),
            )
        )

    moment = now or datetime.now(timezone.utc)
    latest: datetime | None = None
    for obs in observations:
        ts = _parse_ts(obs.timestamp)
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    if latest is not None and moment - latest <= _RECENCY_WINDOW:
        components.append(
            ScoreComponent(
                points=_RECENCY_POINTS,
                reason="latest observation within the last 24h",
            )
        )
    else:
        components.append(
            ScoreComponent(points=0, reason="latest observation older than 24h")
        )

    total = min(sum(c.points for c in components), _MAX_SCORE)
    return total, components, temporal_links


def detect_pivots(
    graph: EntityGraph,
    min_sources: int,
    window_seconds: int,
    verdicts: dict[tuple[str, str], str] | None = None,
    now: datetime | None = None,
) -> list[Pivot]:
    """Every entity seen in ``min_sources``+ source types becomes a pivot.

    Pivots are sorted by descending score, then entity key, so output is
    deterministic.
    """
    verdicts = verdicts or {}
    pivots: list[Pivot] = []
    for entity in graph.entities():
        source_types = graph.source_types_of(entity)
        if len(source_types) < min_sources:
            continue
        observations = graph.observations_of(entity)
        score, components, temporal_links = score_pivot(
            entity, observations, source_types, window_seconds, verdicts, now
        )
        pivots.append(
            Pivot(
                entity=entity,
                source_types=source_types,
                observations=observations,
                score=score,
                components=components,
                verdict=verdicts.get(entity.key()),
                temporal_links=temporal_links,
            )
        )
    pivots.sort(key=lambda p: (-p.score, p.entity.key()))
    return pivots
