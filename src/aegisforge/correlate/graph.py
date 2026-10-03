"""In-memory entity graph over case evidence.

The graph is two dicts: nodes keyed by ``(type, value)`` holding every
observation of that entity, and edges for co-occurrence. It is built
fresh on every ``correlate run`` — nothing is persisted, so correlation
can never modify a case or its evidence.
"""

from __future__ import annotations

from aegisforge.correlate.models import Edge, Entity, Observation


class EntityGraph:
    """Nodes = entities with their observations; edges = co-occurrence."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], list[Observation]] = {}
        self._edges: list[Edge] = []

    def add_observations(self, observations: list[Observation]) -> None:
        for obs in observations:
            self._nodes.setdefault(obs.entity.key(), []).append(obs)

    def add_edges(self, edges: list[Edge]) -> None:
        self._edges.extend(edges)

    def entities(self) -> list[Entity]:
        """All distinct entities, sorted by (type, value) for determinism."""
        return [obs_list[0].entity for _key, obs_list in self._ordered_nodes()]

    def observations_of(self, entity: Entity) -> list[Observation]:
        return list(self._nodes.get(entity.key(), []))

    def source_types_of(self, entity: Entity) -> list[str]:
        """Distinct source types that observed this entity, sorted."""
        seen = {obs.source_type for obs in self._nodes.get(entity.key(), [])}
        return sorted(seen)

    def source_counts(self) -> dict[str, dict[str, int]]:
        """Per-entity counts of observations by source type."""
        counts: dict[str, dict[str, int]] = {}
        for (etype, value), obs_list in self._ordered_nodes():
            per_source: dict[str, int] = {}
            for obs in obs_list:
                per_source[obs.source_type] = per_source.get(obs.source_type, 0) + 1
            counts[f"{etype}:{value}"] = per_source
        return counts

    def edges(self) -> list[Edge]:
        return list(self._edges)

    def node_count(self) -> int:
        return len(self._nodes)

    def _ordered_nodes(self) -> list[tuple[tuple[str, str], list[Observation]]]:
        return sorted(self._nodes.items(), key=lambda kv: kv[0])


def build_graph(observations: list[Observation], edges: list[Edge]) -> EntityGraph:
    """Build the entity graph from extracted observations and edges."""
    graph = EntityGraph()
    graph.add_observations(observations)
    graph.add_edges(edges)
    return graph
