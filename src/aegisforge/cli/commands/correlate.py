"""Correlation engine command implementations."""

from __future__ import annotations

import argparse
from typing import Any

from aegisforge.core.config import AppConfig
from aegisforge.core.findings import Finding
from aegisforge.core.results import Result
from aegisforge.correlate import engine as correlate_engine_mod
from aegisforge.correlate import extract as correlate_extract_mod
from aegisforge.correlate import graph as correlate_graph_mod
from aegisforge.correlate import timeline as correlate_timeline_mod
from aegisforge.intel import engine as intel_engine_mod
from aegisforge.intel.cache import IntelCache
from aegisforge.intel.ratelimit import RateLimiter
from aegisforge.network.validation import ValidationError

from .shared import _case_event, _case_or_fail


def _parse_window(value: str) -> int:
    """Parse '30s'/'5m'/'2h'/'1d' (or plain seconds) into seconds."""
    text = value.strip().lower()
    if text.isdigit():
        seconds = int(text)
    else:
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        if len(text) < 2 or text[-1] not in multipliers or not text[:-1].isdigit():
            raise ValidationError(
                f"invalid --window {value!r}; use like '30s', '5m', '2h', '1d' "
                "or plain seconds"
            )
        seconds = int(text[:-1]) * multipliers[text[-1]]
    if seconds <= 0:
        raise ValidationError("--window must be positive")
    return seconds


def _correlate_intel_lookup(
    args: argparse.Namespace, cfg: AppConfig
) -> tuple[Any, list[str], list[str]]:
    """Resolve intel providers; returns (lookup_fn, notices, network_names).

    The lookup callable enriches pivot entities through the intel engine
    (cache → rate limit → providers). Network providers only run with
    --enrich; the returned network names feed the user-facing notice.
    """
    selected = intel_engine_mod.default_provider_selection(cfg)
    cache = IntelCache(ttl_seconds=int(cfg.get("intel_cache_ttl")))
    limiter = RateLimiter(rate_per_second=float(cfg.get("intel_rate_limit")))
    providers, notices = intel_engine_mod.resolve_providers(
        selected, cfg, enrich=args.enrich
    )

    def lookup(indicators: list[Any]) -> Any:
        try:
            return intel_engine_mod.enrich_indicators(
                indicators, providers, cache, limiter
            )
        finally:
            cache.close()

    notice_texts = [f"[{n.provider}] {n.notice}" for n in notices]
    network_names = sorted({p.name for p in providers if p.network})
    return lookup, notice_texts, network_names


def _pivot_findings(pivots: list[Any], threshold: int) -> list[Finding]:
    """Findings for high-confidence pivots (OBSERVED/INFERRED discipline)."""
    findings: list[Finding] = []
    for pivot in pivots:
        if pivot.score < threshold:
            continue
        entity = pivot.entity
        observed = (
            f"OBSERVED: {entity.type}:{entity.value} seen in "
            f"{len(pivot.source_types)} distinct source types "
            f"({', '.join(pivot.source_types)}). "
        )
        inferred = (
            "INFERRED: the same entity appearing across independent evidence "
            "sources may indicate a pivot point worth investigating — "
            "confirm against the underlying evidence before acting."
        )
        if pivot.verdict == "malicious":
            observed += "Intel verdict: malicious. "
        elif pivot.verdict == "suspicious":
            observed += "Intel verdict: suspicious. "
        findings.append(
            Finding(
                title=f"Correlation pivot: {entity.type}:{entity.value} "
                f"(score {pivot.score})",
                severity="high" if pivot.verdict == "malicious" else "medium",
                confidence=pivot.score,
                reason=observed + inferred,
                evidence=pivot.evidence_refs(),
            )
        )
    return findings


def cmd_correlate_run(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="correlate run", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    window = (
        _parse_window(args.window)
        if isinstance(args.window, str)
        else int(cfg.get("correlate_window_seconds"))
    )
    min_sources = (
        int(args.min_sources)
        if args.min_sources is not None
        else int(cfg.get("correlate_min_sources"))
    )
    if min_sources < 2:
        result.fail("--min-sources must be at least 2")
        return result
    lookup, notices, network_names = _correlate_intel_lookup(args, cfg)
    correlation = correlate_engine_mod.correlate_case(
        case,
        window_seconds=window,
        min_sources=min_sources,
        intel_lookup=lookup,
    )
    data = correlation.to_dict()
    data["notices"] = notices
    if network_names:
        data["network_notice"] = (
            "NOTICE: indicators were sent to network provider(s): "
            + ", ".join(network_names)
            + " — indicators sent to providers leave this machine."
        )
    data["explain"] = bool(args.explain)
    data["score_formula"] = (
        "score = min(100, sources + verdict + temporal + recency); "
        "sources = 10 per distinct source type (cap 40); "
        "verdict = +20 malicious / +10 suspicious; "
        "temporal = +10 when cross-source observations fall within the window; "
        "recency = +10 when the latest observation is within 24h. "
        "Scores describe observation strength, never causation."
    )
    result.data = data
    threshold = int(cfg.get("correlate_pivot_threshold"))
    for finding in _pivot_findings(correlation.pivots, threshold):
        result.add_finding(finding)
    result.summary = (
        f"{args.case_id}: {len(correlation.pivots)} pivot(s) from "
        f"{len(correlation.entities)} entities "
        f"({len(correlation.edges)} co-occurrence edges)"
    )
    if not correlation.pivots:
        result.summary += "; no entity met the min-sources threshold"
    result.add_event(
        _case_event(
            "correlate.run.completed",
            args.case_id,
            {
                "entities": len(correlation.entities),
                "pivots": len(correlation.pivots),
                "window_seconds": window,
                "min_sources": min_sources,
                "enrich": args.enrich,
            },
        )
    )
    return result


def cmd_correlate_entities(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="correlate entities", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    observations, _edges, warnings = correlate_extract_mod.extract_observations(case)
    graph = correlate_graph_mod.build_graph(observations, [])
    rows = []
    for entity in graph.entities():
        obs = graph.observations_of(entity)
        rows.append(
            {
                "type": entity.type,
                "value": entity.value,
                "observations": len(obs),
                "source_types": ", ".join(graph.source_types_of(entity)),
                "evidence_refs": "; ".join(sorted({o.evidence_ref() for o in obs})),
            }
        )
    result.data = {
        "entities": rows,
        "entity_count": len(rows),
        "warnings": warnings,
    }
    result.summary = f"{args.case_id}: {len(rows)} distinct entities"
    result.add_event(
        _case_event(
            "correlate.entities.completed",
            args.case_id,
            {"entities": len(rows)},
        )
    )
    return result


def cmd_correlate_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="correlate timeline", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    window = (
        _parse_window(args.window)
        if isinstance(args.window, str)
        else int(cfg.get("correlate_window_seconds"))
    )
    min_sources = (
        int(args.min_sources)
        if args.min_sources is not None
        else int(cfg.get("correlate_min_sources"))
    )
    if min_sources < 2:
        result.fail("--min-sources must be at least 2")
        return result
    lookup, notices, network_names = _correlate_intel_lookup(args, cfg)
    correlation = correlate_engine_mod.correlate_case(
        case,
        window_seconds=window,
        min_sources=min_sources,
        intel_lookup=lookup,
    )
    timed, untimed = correlate_timeline_mod.build_incident_timeline(
        case, correlation.pivots
    )
    data = correlate_timeline_mod.incident_timeline_to_dict(timed, untimed)
    data["timeline_entries"] = data.pop("timed")
    data["untimed_entries"] = data.pop("untimed")
    data["notices"] = notices
    if network_names:
        data["network_notice"] = (
            "NOTICE: indicators were sent to network provider(s): "
            + ", ".join(network_names)
            + " — indicators sent to providers leave this machine."
        )
    result.data = data
    result.summary = (
        f"{args.case_id}: {len(timed)} timed entr(ies), {len(untimed)} untimed, "
        f"{data['pivot_count']} pivot(s) highlighted"
    )
    result.add_event(
        _case_event(
            "correlate.timeline.completed",
            args.case_id,
            {
                "timed": len(timed),
                "untimed": len(untimed),
                "pivots": data["pivot_count"],
            },
        )
    )
    return result


def render_correlate_run(result: Result) -> str:
    """Human-readable rendering of a `correlate run` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    pivots = data.get("pivots", [])
    lines.append("")
    lines.append(f"Pivots ({len(pivots)}):")
    if not pivots:
        lines.append("  (none — no entity met the min-sources threshold)")
    for pivot in pivots:
        entity = pivot.get("entity", {})
        lines.append(
            f"  [{pivot.get('score', 0):>3}] "
            f"{entity.get('type')}:{entity.get('value')} "
            f"({pivot.get('source_count', 0)} sources: "
            f"{', '.join(pivot.get('source_types', []))})"
            + (f"  verdict: {pivot['verdict']}" if pivot.get("verdict") else "")
        )
        if data.get("explain"):
            for comp in pivot.get("components", []):
                lines.append(
                    f"         +{comp.get('points', 0):>2}: {comp.get('reason')}"
                )
        for link in pivot.get("temporal_links", []):
            lines.append(f"         ~ {link}")
        for ref in pivot.get("evidence_refs", []):
            lines.append(f"         <- {ref}")
    if data.get("explain"):
        lines.append("")
        lines.append("Score formula:")
        lines.append(f"  {data.get('score_formula', '')}")
    for notice in data.get("notices", []):
        lines.append(f"  note: {notice}")
    lines.append("")
    lines.append(
        f"Entities: {data.get('entity_count', 0)}, "
        f"co-occurrence edges: {data.get('edge_count', 0)}, "
        f"window: {data.get('window_seconds', 0)}s, "
        f"min-sources: {data.get('min_sources', 0)}"
    )
    return "\n".join(lines)


def render_correlate_entities(result: Result) -> str:
    """Human-readable rendering of a `correlate entities` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'TYPE':<10}{'VALUE':<44}OBS  SOURCES")
    for row in data.get("entities", []):
        lines.append(
            f"{row.get('type', ''):<10}"
            f"{str(row.get('value', ''))[:43]:<44}"
            f"{row.get('observations', 0):<5}"
            f"{row.get('source_types', '')}"
        )
    for warning in data.get("warnings", []):
        lines.append(f"  warning: {warning}")
    return "\n".join(lines)


def render_correlate_timeline(result: Result) -> str:
    """Human-readable rendering of a `correlate timeline` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    lines.append("")
    for entry in data.get("timeline_entries", []):
        ts = entry.get("timestamp") or "(untimed)"
        marker = ">>> " if entry.get("pivot") else "    "
        lines.append(f"{marker}{ts:<28} [{entry.get('source')}] {entry.get('summary')}")
        if entry.get("pivot") and entry.get("evidence_refs"):
            for ref in entry["evidence_refs"]:
                lines.append(f"         <- {ref}")
    untimed = data.get("untimed_entries", [])
    if untimed:
        lines.append("")
        lines.append(f"Untimed ({len(untimed)}):")
        for entry in untimed:
            lines.append(
                f"    [untimed] [{entry.get('source')}] {entry.get('summary')}"
            )
    return "\n".join(lines)
