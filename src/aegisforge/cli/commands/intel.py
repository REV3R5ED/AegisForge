"""Threat-intel command implementations."""

from __future__ import annotations

import argparse
from typing import Any

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.results import Result
from aegisforge.intel import engine as intel_engine_mod
from aegisforge.intel.cache import IntelCache
from aegisforge.intel.normalize import normalize_indicator
from aegisforge.intel.ratelimit import RateLimiter
from aegisforge.pcap import analyze as pcap_analyze_mod
from aegisforge.pcap.reader import PcapError

from .pcap import _pcap_check, _pcap_options
from .shared import _case_or_fail


def _intel_parts(cfg: AppConfig) -> tuple[IntelCache, RateLimiter]:
    cache = IntelCache(ttl_seconds=int(cfg.get("intel_cache_ttl")))
    limiter = RateLimiter(rate_per_second=float(cfg.get("intel_rate_limit")))
    return cache, limiter


def cmd_intel_lookup(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel lookup", target=args.indicator)
    indicator = normalize_indicator(args.indicator)
    if indicator.rejected:
        result.fail(f"invalid indicator: {indicator.reject_reason}")
        return result
    selected = (
        [args.provider]
        if args.provider
        else intel_engine_mod.default_provider_selection(cfg)
    )
    cache, limiter = _intel_parts(cfg)
    try:
        providers, notices = intel_engine_mod.resolve_providers(
            selected, cfg, enrich=args.enrich, explicit=bool(args.provider)
        )
        enrichment = intel_engine_mod.enrich_indicators(
            [indicator], providers, cache, limiter
        )
    finally:
        cache.close()
    enrichment.notices.extend(notices)
    edata = enrichment.to_dict()
    edata["intel_records"] = edata.pop("records")
    result.data = {
        "indicator": indicator.to_dict(),
        **edata,
    }
    for finding in intel_engine_mod.findings_for_records(enrichment.records):
        result.add_finding(finding)
    verdicts = [r.verdict_label() for r in enrichment.records if not r.skipped]
    result.summary = (
        f"{indicator.value} ({indicator.type}): "
        f"{len(enrichment.records)} record(s); verdicts: "
        f"{', '.join(verdicts) if verdicts else 'none'}"
    )
    if enrichment.network_contacted:
        result.data["network_notice"] = (
            "NOTICE: the indicator was sent to network provider(s): "
            + ", ".join(enrichment.network_contacted)
            + " — indicators sent to providers leave this machine."
        )
    result.add_event(
        Event(
            event_type="intel.lookup.completed",
            source="aegisforge",
            evidence={
                "indicator": indicator.value,
                "type": indicator.type,
                "enrich": args.enrich,
                "providers": [p.name for p in providers],
                "network_contacted": enrichment.network_contacted,
            },
        )
    )
    return result


def _intel_case_indicators(case: Any) -> list[tuple[str, str]]:
    """(indicator value, evidence ref) pairs from a case's finding links."""
    pairs: list[tuple[str, str]] = []
    for finding in case.findings:
        for link in finding.indicators:
            pairs.append((link.value, f"case:{finding.finding_id}"))
    return pairs


def cmd_intel_correlate(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel correlate", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    evidence: list[tuple[Any, list[str]]] = []
    for value, ref in _intel_case_indicators(case):
        ind = normalize_indicator(value)
        evidence.append((ind, [ref]))
    if args.pcap:
        problem = _pcap_check(args.pcap)
        if problem is not None:
            result.fail(problem)
            return result
        try:
            ind_result = pcap_analyze_mod.extract_indicators(
                args.pcap, _pcap_options(args, cfg)
            )
        except PcapError as exc:
            result.fail(str(exc))
            return result
        for item in ind_result.indicators:
            ind = normalize_indicator(item.value)
            evidence.append((ind, [f"pcap:{args.pcap}"]))
    if not evidence:
        result.fail(
            f"{args.case_id} has no linked indicators"
            + (" and no pcap indicators were found" if args.pcap else "")
            + "; link indicators with 'case link' first"
        )
        return result
    selected = intel_engine_mod.default_provider_selection(cfg)
    cache, limiter = _intel_parts(cfg)
    try:
        providers, notices = intel_engine_mod.resolve_providers(
            selected, cfg, enrich=args.enrich
        )
        correlation = intel_engine_mod.correlate(evidence, providers, cache, limiter)
    finally:
        cache.close()
    correlation.notices.extend(notices)
    cdata = correlation.to_dict()
    cdata["intel_rows"] = cdata.pop("rows")
    cdata["intel_records"] = cdata.pop("records")
    result.data = cdata
    for finding in intel_engine_mod.findings_for_records(correlation.records):
        result.add_finding(finding)
    malicious = sum(1 for r in correlation.rows if r.combined_verdict == "malicious")
    conflicting = sum(
        1 for r in correlation.rows if r.combined_verdict == "conflicting"
    )
    result.summary = (
        f"{args.case_id}: {len(correlation.rows)} indicator(s) correlated, "
        f"{malicious} malicious, {conflicting} conflicting"
    )
    if correlation.network_contacted:
        result.data["network_notice"] = (
            "NOTICE: indicators were sent to network provider(s): "
            + ", ".join(correlation.network_contacted)
            + " — indicators sent to providers leave this machine."
        )
    result.add_event(
        Event(
            event_type="intel.correlate.completed",
            source="aegisforge",
            evidence={
                "case_id": args.case_id,
                "indicators": len(correlation.rows),
                "enrich": args.enrich,
                "network_contacted": correlation.network_contacted,
            },
        )
    )
    return result


def cmd_intel_providers(args: argparse.Namespace, cfg: AppConfig) -> Result:
    from aegisforge.intel.providers import get_provider, provider_names

    result = Result(command="intel providers")
    rows = []
    for name in provider_names():
        cls = get_provider(name)
        instance = cls()
        intel_engine_mod._configure_provider(instance, cfg)
        rows.append(
            {
                "name": name,
                "network": cls.network,
                "supported_types": list(cls.supported_types),
                "configured": instance.is_configured(),
                "default_confidence": cls.default_confidence,
            }
        )
    result.data = {"providers": rows}
    result.summary = f"{len(rows)} registered provider(s)"
    return result


def cmd_intel_cache_clear(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="intel cache-clear")
    cache = IntelCache(ttl_seconds=int(cfg.get("intel_cache_ttl")))
    try:
        removed = cache.clear()
    finally:
        cache.close()
    result.data = {"removed_entries": removed}
    result.summary = f"intel cache cleared: {removed} entr(ies) removed"
    result.add_event(
        Event(
            event_type="intel.cache.cleared",
            source="aegisforge",
            evidence={"removed_entries": removed},
        )
    )
    return result


# Correlation engine (v0.9)


def render_intel_lookup(result: Result) -> str:
    """Human-readable rendering of an `intel lookup` result."""
    data = result.data
    indicator = data.get("indicator", {})
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"Indicator: {indicator.get('value')} ({indicator.get('type')})")
    if indicator.get("defanged"):
        lines.append("  (input was defanged; refanged before lookup)")
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    lines.append("")
    lines.append(f"{'PROVIDER':<22}{'VERDICT':<14}{'CONF':<6}DETAIL")
    for rec in data.get("intel_records", []):
        if rec.get("skipped"):
            lines.append(
                f"{rec.get('provider', ''):<22}{'skipped':<14}{'-':<6}"
                f"{rec.get('skip_reason', '')}"
            )
            continue
        lines.append(
            f"{rec.get('provider', ''):<22}"
            f"{rec.get('verdict_label', rec.get('verdict', '')):<14}"
            f"{rec.get('confidence', ''):<6}"
            f"{str(rec.get('detail', ''))[:70]}"
        )
    for notice in data.get("notices", []):
        lines.append(f"  note [{notice.get('provider')}]: {notice.get('notice')}")
    return "\n".join(lines)


def render_intel_correlate(result: Result) -> str:
    """Human-readable rendering of an `intel correlate` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    if data.get("network_notice"):
        lines.append("")
        lines.append(data["network_notice"])
    lines.append("")
    lines.append(f"{'INDICATOR':<40}{'TYPE':<8}{'VERDICT':<12}PROVIDERS / EVIDENCE")
    for row in data.get("intel_rows", []):
        lines.append(
            f"{str(row.get('indicator'))[:39]:<40}"
            f"{row.get('indicator_type', ''):<8}"
            f"{row.get('combined_verdict', ''):<12}"
            f"{', '.join(row.get('providers_hit', []))}"
        )
        for ref in row.get("local_evidence", []):
            lines.append(f"{'':<60}<- {ref}")
    for notice in data.get("notices", []):
        lines.append(f"  note [{notice.get('provider')}]: {notice.get('notice')}")
    return "\n".join(lines)


def render_intel_providers(result: Result) -> str:
    """Human-readable rendering of an `intel providers` result."""
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'NAME':<22}{'NETWORK':<9}{'CONFIGURED':<11}TYPES")
    for p in result.data.get("providers", []):
        lines.append(
            f"{p.get('name', ''):<22}"
            f"{'yes' if p.get('network') else 'no':<9}"
            f"{'yes' if p.get('configured') else 'no':<11}"
            f"{', '.join(p.get('supported_types', []))}"
        )
    lines.append("")
    lines.append(
        "Network providers run only with --enrich; without it, lookups "
        "stay local (blocklist + cache)."
    )
    return "\n".join(lines)


def render_intel_cache_clear(result: Result) -> str:
    """Human-readable rendering of an `intel cache-clear` result."""
    lines = [result.summary] if result.summary else []
    return "\n".join(lines)
