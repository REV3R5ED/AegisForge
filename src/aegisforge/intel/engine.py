"""Lookup orchestration and correlation with local evidence.

The engine enforces the two hard rules from
:mod:`aegisforge.intel.providers`:

- network providers run only when explicitly configured *and* the caller
  asked for enrichment (``enrich=True``);
- cache hits never consume rate-limit budget.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.config import AppConfig
from aegisforge.core.findings import Finding
from aegisforge.intel import builtin  # noqa: F401  (registers providers)
from aegisforge.intel.cache import IntelCache
from aegisforge.intel.models import NO_VERDICT, IntelRecord, NormalizedIndicator
from aegisforge.intel.providers import IntelProvider, get_provider, provider_names
from aegisforge.intel.ratelimit import RateLimiter

#: Verdicts that count as "signal" when combining provider answers.
_SIGNAL_VERDICTS = ("malicious", "suspicious", "clean")


def _record_from_dict(data: dict[str, Any]) -> IntelRecord:
    fields = (
        "indicator",
        "indicator_type",
        "provider",
        "verdict",
        "confidence",
        "detail",
        "raw",
        "cached",
        "skipped",
        "skip_reason",
        "looked_up_at",
    )
    return IntelRecord(**{k: data[k] for k in fields if k in data})


@dataclass
class ProviderNotice:
    provider: str
    notice: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_providers(
    selected: list[str],
    cfg: AppConfig,
    enrich: bool,
    explicit: bool = False,
) -> tuple[list[IntelProvider], list[ProviderNotice]]:
    """Instantiate and configure *selected* providers.

    Network providers are dropped unless ``enrich`` is True. Providers
    that are not configured are dropped from sweeps (with a notice);
    when ``explicit`` is True (user named ``--provider``), they are kept
    so the caller can report "not configured" cleanly per indicator.
    """
    active: list[IntelProvider] = []
    notices: list[ProviderNotice] = []
    for name in selected:
        try:
            cls = get_provider(name)
        except KeyError:
            notices.append(ProviderNotice(name, f"unknown provider {name!r}"))
            continue
        provider = cls()
        _configure_provider(provider, cfg)
        if provider.network and not enrich:
            notices.append(
                ProviderNotice(
                    name,
                    "network provider skipped: pass --enrich to allow network lookups",
                )
            )
            continue
        if not provider.is_configured() and not explicit:
            notices.append(ProviderNotice(name, "provider not configured; skipped"))
            continue
        active.append(provider)
    return active, notices


def _configure_provider(provider: IntelProvider, cfg: AppConfig) -> None:
    """Feed a provider its settings from the app config."""
    settings: dict[str, Any] = {}
    if provider.name == "local-blocklist":
        settings["path"] = cfg.get("intel_blocklist")
    provider.configure(settings)


def default_provider_selection(cfg: AppConfig) -> list[str]:
    selected = cfg.get("intel_providers")
    if isinstance(selected, list) and selected:
        return [str(s) for s in selected]
    return ["local-blocklist"]


@dataclass
class EnrichmentResult:
    records: list[IntelRecord] = field(default_factory=list)
    network_contacted: list[str] = field(default_factory=list)
    notices: list[ProviderNotice] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "network_contacted": self.network_contacted,
            "notices": [n.to_dict() for n in self.notices],
        }


def enrich_indicators(
    indicators: list[NormalizedIndicator],
    providers: list[IntelProvider],
    cache: IntelCache,
    limiter: RateLimiter,
) -> EnrichmentResult:
    """Run *indicators* through *providers* (cache → rate limit → lookup)."""
    result = EnrichmentResult()
    result.network_contacted = sorted({p.name for p in providers if p.network})
    for provider in providers:
        for ind in indicators:
            if ind.rejected:
                continue
            if ind.type not in provider.supported_types:
                continue
            if not provider.is_configured():
                result.records.append(
                    IntelRecord(
                        indicator=ind.value,
                        indicator_type=ind.type,
                        provider=provider.name,
                        verdict=NO_VERDICT,
                        confidence=0,
                        detail=f"provider {provider.name!r} is not configured",
                        skipped=True,
                        skip_reason="not configured",
                    )
                )
                continue
            cached = cache.get(provider.name, ind.type, ind.value)
            if cached is not None:
                result.records.append(_record_from_dict(cached))
                continue
            if not limiter.acquire(provider.name):
                wait = limiter.retry_after(provider.name)
                result.records.append(
                    IntelRecord(
                        indicator=ind.value,
                        indicator_type=ind.type,
                        provider=provider.name,
                        verdict=NO_VERDICT,
                        confidence=0,
                        detail="rate-limit budget spent; lookup skipped, not attempted",
                        skipped=True,
                        skip_reason=f"rate limited (retry in {wait:.1f}s)",
                    )
                )
                continue
            try:
                record = provider.lookup(ind)
            except Exception as exc:  # defensive: providers must not raise
                record = IntelRecord(
                    indicator=ind.value,
                    indicator_type=ind.type,
                    provider=provider.name,
                    verdict="unknown",
                    confidence=0,
                    detail=f"provider raised {type(exc).__name__}: {exc}",
                    raw={"error": str(exc)},
                )
            cache.put(provider.name, ind.type, ind.value, record)
            result.records.append(record)
    return result


def findings_for_records(records: list[IntelRecord]) -> list[Finding]:
    """High findings for ``malicious`` verdicts (observed vs inferred)."""
    findings: list[Finding] = []
    for record in records:
        if record.skipped or record.verdict != "malicious":
            continue
        findings.append(
            Finding(
                title=f"Intel verdict malicious: {record.indicator}",
                severity="high",
                confidence=record.confidence,
                reason=(
                    f"OBSERVED: provider {record.provider!r} returned verdict "
                    f"'malicious' for {record.indicator_type} "
                    f"{record.indicator!r} (confidence {record.confidence}). "
                    f"INFERRED: the indicator may be associated with malicious "
                    f"activity — confirm against additional sources before acting."
                ),
                evidence=[record.detail],
                data={"indicator": record.indicator, "provider": record.provider},
            )
        )
    return findings


def combine_verdicts(records: list[IntelRecord]) -> str:
    """One combined verdict across providers.

    Distinct signal verdicts (ignoring ``unknown``/``no-verdict``) that
    disagree produce ``"conflicting"`` — verdicts are never averaged.
    """
    signal = {
        r.verdict for r in records if r.verdict in _SIGNAL_VERDICTS and not r.skipped
    }
    if not signal:
        return "unknown"
    if len(signal) > 1:
        return "conflicting"
    return next(iter(signal))


@dataclass
class CorrelationRow:
    indicator: str
    indicator_type: str
    providers_hit: list[str]
    combined_verdict: str
    local_evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationResult:
    rows: list[CorrelationRow] = field(default_factory=list)
    records: list[IntelRecord] = field(default_factory=list)
    network_contacted: list[str] = field(default_factory=list)
    notices: list[ProviderNotice] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows": [r.to_dict() for r in self.rows],
            "records": [r.to_dict() for r in self.records],
            "network_contacted": self.network_contacted,
            "notices": [n.to_dict() for n in self.notices],
        }


def correlate(
    evidence: list[tuple[NormalizedIndicator, list[str]]],
    providers: list[IntelProvider],
    cache: IntelCache,
    limiter: RateLimiter,
) -> CorrelationResult:
    """Enrich indicators carrying local-evidence references.

    *evidence* is ``(indicator, [evidence refs])`` pairs, e.g.
    ``("203.0.113.7", ["case:CASE-2026-001-F01", "pcap:capture.pcap"])``.
    """
    result = CorrelationResult()
    by_key: dict[tuple[str, str], list[str]] = {}
    ordered: list[NormalizedIndicator] = []
    for ind, refs in evidence:
        if ind.rejected:
            continue
        key = (ind.type, ind.value)
        if key not in by_key:
            by_key[key] = []
            ordered.append(ind)
        for ref in refs:
            if ref not in by_key[key]:
                by_key[key].append(ref)
    enrichment = enrich_indicators(ordered, providers, cache, limiter)
    result.records = enrichment.records
    result.network_contacted = enrichment.network_contacted
    result.notices = enrichment.notices
    for ind in ordered:
        key = (ind.type, ind.value)
        recs = [r for r in enrichment.records if (r.indicator_type, r.indicator) == key]
        hits = sorted({r.provider for r in recs if not r.skipped})
        result.rows.append(
            CorrelationRow(
                indicator=ind.value,
                indicator_type=ind.type,
                providers_hit=hits,
                combined_verdict=combine_verdicts(recs),
                local_evidence=sorted(by_key[key]),
            )
        )
    return result


__all__ = ["provider_names"]
