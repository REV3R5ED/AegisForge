"""Tests for the v0.8 threat-intel module: normalization, verdict
vocabulary, providers, cache, rate limiting, engine orchestration and
CLI wiring."""

from __future__ import annotations

import csv
import json
import time

import pytest

from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.intel import builtin  # noqa: F401  (registers providers)
from aegisforge.intel import engine as intel_engine_mod
from aegisforge.intel.cache import IntelCache
from aegisforge.intel.models import (
    NO_VERDICT,
    IntelRecord,
)
from aegisforge.intel.normalize import normalize_indicator, normalize_indicators
from aegisforge.intel.providers import (
    IntelProvider,
    get_provider,
    provider_names,
    register_provider,
)
from aegisforge.intel.ratelimit import RateLimiter

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_ip_variants():
    ind = normalize_indicator("  203.0.113.7 ")
    assert ind.type == "ip" and ind.value == "203.0.113.7"
    ind = normalize_indicator("::1")
    assert ind.type == "ip" and ind.value == "::1"


def test_normalize_domain_case_and_trailing_dot():
    ind = normalize_indicator("EVIL.EXAMPLE.COM.")
    assert ind.type == "domain" and ind.value == "evil.example.com"


def test_normalize_url_keeps_full_url_and_domain():
    ind = normalize_indicator("https://Example.COM:8443/path?q=1#frag")
    assert ind.type == "url"
    assert ind.value == "example.com"
    assert ind.domain == "example.com"
    assert ind.url.startswith("https://")


def test_normalize_defanged_variants():
    for raw in (
        "hxxp://evil[.]example[.]com/x",
        "hxtp://evil.example.com",
        "http://1.2.3[.]4/",
        "https://evil(.)example(.)com",
    ):
        ind = normalize_indicator(raw)
        assert ind.defanged, raw
        assert not ind.rejected, raw


def test_normalize_hashes():
    assert normalize_indicator("d41d8cd98f00b204e9800998ecf8427e").hash_kind == "md5"
    ind = normalize_indicator("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
    assert ind.type == "hash" and ind.hash_kind == "sha1"
    assert ind.value == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ind = normalize_indicator(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert ind.hash_kind == "sha256"


def test_normalize_rejects_with_reason():
    for raw in ("", "   ", "not_an_indicator!!!", "http://", "notahexhash!!"):
        ind = normalize_indicator(raw)
        assert ind.rejected, raw
        assert ind.reject_reason, raw
    # 31 hex chars is not a valid hash length
    ind = normalize_indicator("d41d8cd98f00b204e9800998ecf8427")
    assert ind.rejected


def test_normalize_batch():
    out = normalize_indicators(["1.2.3.4", "bogus!!!"])
    assert len(out) == 2
    assert not out[0].rejected
    assert out[1].rejected


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------


def test_verdict_vocabulary_enforced():
    for verdict in ("unknown", "clean", "suspicious", "malicious", NO_VERDICT):
        IntelRecord(
            indicator="1.2.3.4",
            indicator_type="ip",
            provider="x",
            verdict=verdict,
        )
    for bad in ("evil", "bad", "compromised", "MALICIOUS", "", "conflicting"):
        with pytest.raises(ValueError):
            IntelRecord(
                indicator="1.2.3.4",
                indicator_type="ip",
                provider="x",
                verdict=bad,
            )


def test_verdict_label_expands_no_verdict():
    rec = IntelRecord(indicator="1.2.3.4", indicator_type="ip", provider="x")
    assert rec.verdict == NO_VERDICT
    assert rec.verdict_label() == "provider did not return a verdict"


def test_confidence_bounds_enforced():
    with pytest.raises(ValueError):
        IntelRecord(indicator="x", indicator_type="ip", provider="p", confidence=101)


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------


def test_builtin_providers_registered():
    names = provider_names()
    for expected in (
        "local-blocklist",
        "team-cymru",
        "dns-resolve",
        "http-reputation-stub",
    ):
        assert expected in names


def test_registry_rejects_duplicates_and_unknown():
    with pytest.raises(ValueError):

        @register_provider
        class Dup(IntelProvider):
            name = "local-blocklist"

            def is_configured(self):
                return True

            def lookup(self, indicator):
                raise AssertionError

    with pytest.raises(KeyError):
        get_provider("no-such-provider")


def test_stub_provider_never_configured():
    cls = get_provider("http-reputation-stub")
    assert not cls().is_configured()
    rec = cls().lookup(normalize_indicator("1.2.3.4"))
    assert rec.verdict == NO_VERDICT
    assert "STUB" in rec.detail


# ---------------------------------------------------------------------------
# Local blocklist
# ---------------------------------------------------------------------------


@pytest.fixture()
def blocklist_csv(tmp_path):
    path = tmp_path / "blocklist.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["indicator", "type", "source", "confidence", "note"])
        writer.writerow(["203.0.113.7", "ip", "TestList", "90", "test entry"])
        writer.writerow(["evil.example.com", "domain", "TestList", "75", "phish"])
        writer.writerow(["notahex", "ip", "TestList", "", ""])
    return str(path)


def test_blocklist_hit_miss_and_fallback(blocklist_csv):
    cls = get_provider("local-blocklist")
    prov = cls()
    prov.configure({"path": blocklist_csv})
    assert prov.is_configured()

    hit = prov.lookup(normalize_indicator("203.0.113.7"))
    assert hit.verdict == "malicious"
    assert hit.confidence == 90
    assert "TestList" in hit.detail

    miss = prov.lookup(normalize_indicator("8.8.8.8"))
    assert miss.verdict == "unknown"

    # URL whose domain is blocklisted matches via domain fallback.
    url_hit = prov.lookup(normalize_indicator("http://evil.example.com/x"))
    assert url_hit.verdict == "malicious"


def test_blocklist_not_configured_without_path():
    cls = get_provider("local-blocklist")
    assert not cls().is_configured()
    cls2 = get_provider("local-blocklist")
    prov = cls2()
    prov.configure({"path": "/nonexistent/blocklist.csv"})
    assert not prov.is_configured()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_miss_and_clear(tmp_path):
    cache = IntelCache(path=tmp_path / "c.sqlite3", ttl_seconds=60)
    assert cache.get("p", "ip", "1.2.3.4") is None
    rec = IntelRecord(
        indicator="1.2.3.4",
        indicator_type="ip",
        provider="p",
        verdict="clean",
        confidence=80,
    )
    cache.put("p", "ip", "1.2.3.4", rec)
    hit = cache.get("p", "ip", "1.2.3.4")
    assert hit is not None and hit["verdict"] == "clean" and hit["cached"] is True
    assert cache.clear() == 1
    assert cache.get("p", "ip", "1.2.3.4") is None
    cache.close()


def test_cache_ttl_expiry(tmp_path):
    cache = IntelCache(path=tmp_path / "c.sqlite3", ttl_seconds=1)
    rec = IntelRecord(indicator="x", indicator_type="domain", provider="p")
    cache.put("p", "domain", "x", rec)
    assert cache.get("p", "domain", "x") is not None
    time.sleep(1.1)
    assert cache.get("p", "domain", "x") is None
    cache.close()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def test_rate_limiter_budget_and_refill():
    limiter = RateLimiter(rate_per_second=2.0, capacity=2)
    assert limiter.acquire("p")
    assert limiter.acquire("p")
    assert not limiter.acquire("p")
    assert limiter.retry_after("p") > 0
    time.sleep(0.6)
    assert limiter.acquire("p")


def test_rate_limiter_rejects_bad_rate():
    with pytest.raises(ValueError):
        RateLimiter(rate_per_second=0)


# ---------------------------------------------------------------------------
# Engine orchestration
# ---------------------------------------------------------------------------


def _engine_parts(tmp_path, **cfg_over):
    from aegisforge.core.config import DEFAULTS, AppConfig

    values = dict(DEFAULTS)
    values.update(cfg_over)
    cfg = AppConfig(values=values)
    cache = IntelCache(path=tmp_path / "c.sqlite3", ttl_seconds=3600)
    limiter = RateLimiter(rate_per_second=1000.0)
    return cfg, cache, limiter


def test_no_enrich_means_no_network(tmp_path, monkeypatch, blocklist_csv):
    """Without --enrich, network providers are never invoked."""
    import socket as socket_mod

    def _boom(*a, **k):
        raise AssertionError("network call made without --enrich")

    monkeypatch.setattr(socket_mod, "getaddrinfo", _boom)
    cfg, cache, limiter = _engine_parts(
        tmp_path,
        intel_providers=["local-blocklist", "dns-resolve", "team-cymru"],
        intel_blocklist=blocklist_csv,
    )
    providers, notices = intel_engine_mod.resolve_providers(
        ["local-blocklist", "dns-resolve", "team-cymru"], cfg, enrich=False
    )
    assert [p.name for p in providers] == ["local-blocklist"]
    assert any("enrich" in n.notice for n in notices)
    result = intel_engine_mod.enrich_indicators(
        [normalize_indicator("example.com")], providers, cache, limiter
    )
    assert result.network_contacted == []
    cache.close()


def test_enrich_contacts_network_with_notice(tmp_path, monkeypatch, blocklist_csv):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, None, ("93.184.216.34", 0))],
    )
    import socket

    cfg, cache, limiter = _engine_parts(
        tmp_path, intel_providers=["dns-resolve"], intel_blocklist=blocklist_csv
    )
    providers, _ = intel_engine_mod.resolve_providers(["dns-resolve"], cfg, enrich=True)
    result = intel_engine_mod.enrich_indicators(
        [normalize_indicator("example.com")], providers, cache, limiter
    )
    assert result.network_contacted == ["dns-resolve"]
    rec = result.records[0]
    assert rec.verdict == "unknown"
    assert "currently resolves to" in rec.detail
    cache.close()


def test_explicit_unconfigured_provider_reports_cleanly(tmp_path):
    cfg, cache, limiter = _engine_parts(tmp_path)
    providers, _ = intel_engine_mod.resolve_providers(
        ["http-reputation-stub"], cfg, enrich=False, explicit=True
    )
    assert len(providers) == 1
    result = intel_engine_mod.enrich_indicators(
        [normalize_indicator("1.2.3.4")], providers, cache, limiter
    )
    rec = result.records[0]
    assert rec.skipped and rec.skip_reason == "not configured"
    assert rec.verdict == NO_VERDICT
    cache.close()


def test_cache_hit_skips_rate_limit_and_lookup(tmp_path, blocklist_csv):
    cfg, cache, limiter = _engine_parts(tmp_path, intel_blocklist=blocklist_csv)
    providers, _ = intel_engine_mod.resolve_providers(
        ["local-blocklist"], cfg, enrich=False
    )
    ind = normalize_indicator("203.0.113.7")
    first = intel_engine_mod.enrich_indicators([ind], providers, cache, limiter)
    assert not first.records[0].cached
    # Drain the budget entirely; the cached hit must still go through.
    for _ in range(2000):
        limiter.acquire("local-blocklist")
    second = intel_engine_mod.enrich_indicators([ind], providers, cache, limiter)
    assert second.records[0].cached is True
    assert second.records[0].verdict == "malicious"
    cache.close()


def test_malicious_verdicts_become_high_findings():
    rec = IntelRecord(
        indicator="203.0.113.7",
        indicator_type="ip",
        provider="local-blocklist",
        verdict="malicious",
        confidence=90,
        detail="blocklisted",
    )
    findings = intel_engine_mod.findings_for_records([rec])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "OBSERVED" in findings[0].reason and "INFERRED" in findings[0].reason
    clean = IntelRecord(
        indicator="8.8.8.8", indicator_type="ip", provider="p", verdict="clean"
    )
    assert intel_engine_mod.findings_for_records([clean]) == []


def test_combine_verdicts_conflicting_never_averaged():
    def rec(verdict):
        return IntelRecord(
            indicator="x", indicator_type="ip", provider="p", verdict=verdict
        )

    assert (
        intel_engine_mod.combine_verdicts([rec("malicious"), rec("clean")])
        == "conflicting"
    )
    assert (
        intel_engine_mod.combine_verdicts([rec("malicious"), rec("malicious")])
        == "malicious"
    )
    assert (
        intel_engine_mod.combine_verdicts([rec("unknown"), rec(NO_VERDICT)])
        == "unknown"
    )
    assert intel_engine_mod.combine_verdicts([]) == "unknown"


def test_correlate_merges_evidence_refs(tmp_path, blocklist_csv):
    cfg, cache, limiter = _engine_parts(tmp_path, intel_blocklist=blocklist_csv)
    providers, _ = intel_engine_mod.resolve_providers(
        ["local-blocklist"], cfg, enrich=False
    )
    evidence = [
        (normalize_indicator("203.0.113.7"), ["case:CASE-1-F01", "pcap:a.pcap"]),
        (normalize_indicator("203.0.113.7"), ["case:CASE-1-F02"]),
    ]
    result = intel_engine_mod.correlate(evidence, providers, cache, limiter)
    assert len(result.rows) == 1
    row = result.rows[0]
    assert row.combined_verdict == "malicious"
    assert sorted(row.local_evidence) == [
        "case:CASE-1-F01",
        "case:CASE-1-F02",
        "pcap:a.pcap",
    ]
    assert row.providers_hit == ["local-blocklist"]
    cache.close()


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


@pytest.fixture()
def intel_cli(tmp_path, monkeypatch, blocklist_csv):
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(tmp_path / "state"))
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps({"intel_blocklist": blocklist_csv}), encoding="utf-8"
    )
    return ["--config", str(cfg_path)]


def test_cli_lookup_hit_and_miss(intel_cli):
    assert cli_main.main(intel_cli + ["intel", "lookup", "203.0.113.7"]) == 1
    assert cli_main.main(intel_cli + ["intel", "lookup", "8.8.8.8"]) == 0


def test_cli_lookup_invalid_indicator(intel_cli):
    assert cli_main.main(intel_cli + ["intel", "lookup", "bogus!!!"]) == 2


def test_cli_lookup_json_and_csv(intel_cli, capsys):
    assert cli_main.main(intel_cli + ["intel", "lookup", "203.0.113.7", "--json"]) == 1
    out = capsys.readouterr().out
    assert '"verdict": "malicious"' in out
    assert cli_main.main(intel_cli + ["intel", "lookup", "203.0.113.7", "--csv"]) == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("indicator,type,provider")


def test_cli_providers_lists_all(intel_cli, capsys):
    assert cli_main.main(intel_cli + ["intel", "providers"]) == 0
    out = capsys.readouterr().out
    assert "local-blocklist" in out and "team-cymru" in out


def test_cli_cache_clear(intel_cli, capsys):
    cli_main.main(intel_cli + ["intel", "lookup", "203.0.113.7"])
    capsys.readouterr()
    assert cli_main.main(intel_cli + ["intel", "cache-clear"]) == 0
    out = capsys.readouterr().out
    assert "1 entr" in out


def test_cli_correlate_needs_indicators(intel_cli, tmp_path):
    cli_main.main(intel_cli + ["case", "create", "--title", "t"])
    code = cli_main.main(intel_cli + ["intel", "correlate", "--case", "CASE-2026-001"])
    assert code == 2


def test_cli_correlate_full_flow(intel_cli):
    cli_main.main(intel_cli + ["case", "create", "--title", "t"])
    cli_main.main(
        intel_cli
        + [
            "case",
            "finding",
            "CASE-2026-001",
            "--title",
            "f",
            "--severity",
            "high",
            "--confidence",
            "80",
            "--detail",
            "d",
        ]
    )
    cli_main.main(
        intel_cli
        + [
            "case",
            "link",
            "CASE-2026-001",
            "--finding",
            "CASE-2026-001-F01",
            "--indicator",
            "203.0.113.7",
        ]
    )
    code = cli_main.main(intel_cli + ["intel", "correlate", "--case", "CASE-2026-001"])
    assert code == 1  # malicious verdict -> high finding -> exit 1


def test_cli_lookup_unknown_provider(intel_cli, capsys):
    code = cli_main.main(
        intel_cli + ["intel", "lookup", "1.2.3.4", "--provider", "nope"]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "unknown provider" in out


def test_plugin_registered():
    info = get_registry().get("intel")
    assert info.version == "0.8.0"
    assert "intel lookup" in info.commands


def test_config_knobs_present():
    from aegisforge.core.config import DEFAULTS

    for knob in (
        "intel_providers",
        "intel_cache_ttl",
        "intel_rate_limit",
        "intel_blocklist",
    ):
        assert knob in DEFAULTS
