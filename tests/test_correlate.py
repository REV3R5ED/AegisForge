"""Tests for the v0.9 correlation engine: entities, graph, pivots,
scoring, temporal correlation, incident timelines and CLI wiring."""

from __future__ import annotations

import hashlib
import io
import json
import struct as _struct
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.correlate import engine as engine_mod
from aegisforge.correlate import entities as entities_mod
from aegisforge.correlate import extract as extract_mod
from aegisforge.correlate import graph as graph_mod
from aegisforge.correlate import scoring as scoring_mod
from aegisforge.correlate import timeline as timeline_mod
from aegisforge.correlate.models import Edge, Entity, Observation, Pivot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main.main(argv)
    return code, buf.getvalue()


@pytest.fixture()
def cases_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(state))
    return state


def _syslog(path: Path) -> Path:
    path.write_text(
        "Oct  3 02:10:01 web sshd[1]: Failed password for root from 203.0.113.7\n"
        "Oct  3 02:11:05 web sshd[2]: Failed password for admin from 203.0.113.7\n",
        encoding="utf-8",
    )
    return path


def _make_case(cases_home: Path) -> str:
    code, out = _run_cli(["case", "create", "--title", "Correlation test"])
    assert code == 0
    case_id = out.strip().splitlines()[0].split()[1]
    log = _syslog(cases_home / "auth.log")
    code, _ = _run_cli(
        ["case", "attach", case_id, "--kind", "logs", "--source", str(log)]
    )
    assert code == 0
    code, _ = _run_cli(
        [
            "case",
            "finding",
            case_id,
            "--title",
            "SSH brute force",
            "--severity",
            "high",
            "--confidence",
            "80",
            "--detail",
            "brute force",
        ]
    )
    assert code == 1  # findings produce exit 1
    code, _ = _run_cli(
        [
            "case",
            "link",
            case_id,
            "--finding",
            f"{case_id}-F01",
            "--indicator",
            "203.0.113.7",
        ]
    )
    assert code == 0
    return case_id


def _obs(
    value: str,
    type: str,
    source_type: str,
    ts: str | None = None,
    label: str = "logs:auth.log",
    eid: str = "CASE-2026-001-E01",
) -> Observation:
    return Observation(
        entity=Entity(value=value, type=type),
        source_type=source_type,
        source_label=label,
        evidence_id=eid,
        timestamp=ts,
        detail="test",
    )


# ---------------------------------------------------------------------------
# Entity normalization
# ---------------------------------------------------------------------------


def test_normalize_user_variants():
    assert entities_mod.normalize_user("ROOT") == "root"
    assert entities_mod.normalize_user("CORP\\Alice") == "alice@corp"
    assert entities_mod.normalize_user("bob@Example.COM") == "bob@example.com"
    assert entities_mod.normalize_user("") is None
    assert entities_mod.normalize_user("bad user") is None


def test_normalize_hostname_variants():
    assert entities_mod.normalize_hostname("Web01.EXAMPLE.com.") == "web01.example.com"
    assert entities_mod.normalize_hostname("web") == "web"
    assert entities_mod.normalize_hostname("bad..host") is None
    assert entities_mod.normalize_hostname("") is None


def test_normalize_entity_types():
    assert entities_mod.normalize_entity("10.0.0.1") == Entity("10.0.0.1", "ip")
    assert entities_mod.normalize_entity("::1") == Entity("::1", "ip")
    assert entities_mod.normalize_entity("Example.COM.") == Entity(
        "example.com", "domain"
    )
    # Bare single labels are ambiguous; user wins over hostname by design.
    assert entities_mod.normalize_entity("web01") == Entity("web01", "user")
    assert entities_mod.normalize_entity("CORP\\root") == Entity("root@corp", "user")
    assert entities_mod.normalize_entity("!!!") is None
    assert entities_mod.normalize_entity("") is None


def test_normalize_entity_type_hint():
    assert entities_mod.normalize_entity("root", type_hint="user") == Entity(
        "root", "user"
    )
    assert entities_mod.normalize_entity("10.0.0.1", type_hint="domain") is None
    with pytest.raises(ValueError):
        entities_mod.normalize_entity("x", type_hint="bogus")


def test_extract_from_text():
    entities = extract_mod.extract_from_text(
        "Failed password for root from 203.0.113.7 via https://evil.example.com/x"
    )
    keys = {e.key() for e in entities}
    assert ("ip", "203.0.113.7") in keys
    assert ("user", "root") in keys
    assert ("domain", "evil.example.com") in keys
    # 999.999.999.999 is not a valid IP and must not appear.
    assert not any(v == "999.999.999.999" for _, v in keys)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


def test_graph_nodes_edges_deterministic():
    graph = graph_mod.build_graph(
        [
            _obs("10.0.0.1", "ip", "logs"),
            _obs("10.0.0.1", "ip", "network"),
            _obs("root", "user", "logs"),
        ],
        [
            Edge(
                entity_a=Entity("10.0.0.1", "ip"),
                entity_b=Entity("root", "user"),
                evidence_refs=["logs:auth.log [E01]"],
            )
        ],
    )
    assert graph.node_count() == 2
    assert [e.key() for e in graph.entities()] == [
        ("ip", "10.0.0.1"),
        ("user", "root"),
    ]
    assert graph.source_types_of(Entity("10.0.0.1", "ip")) == ["logs", "network"]
    assert graph.source_counts()["ip:10.0.0.1"] == {"logs": 1, "network": 1}
    assert len(graph.edges()) == 1


def test_edge_requires_evidence():
    with pytest.raises(ValueError):
        Edge(
            entity_a=Entity("a", "ip"),
            entity_b=Entity("b", "ip"),
            evidence_refs=[],
        )


def test_pivot_requires_observations():
    with pytest.raises(ValueError):
        Pivot(
            entity=Entity("10.0.0.1", "ip"),
            source_types=["logs"],
            observations=[],
        )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_score_breakdown_arithmetic():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    ts = "2026-10-03T11:30:00Z"
    obs = [
        _obs("203.0.113.7", "ip", "logs", ts),
        _obs("203.0.113.7", "ip", "network", ts),
    ]
    score, components, links = scoring_mod.score_pivot(
        Entity("203.0.113.7", "ip"),
        obs,
        ["logs", "network"],
        3600,
        {("ip", "203.0.113.7"): "malicious"},
        now=now,
    )
    by_reason = {c.reason: c.points for c in components}
    assert sum(by_reason.values()) == score == 60  # 20 + 20 + 10 + 10
    assert links, "observations 0s apart must link within 1h"


def test_score_no_verdict_no_temporal():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    obs = [
        _obs("10.0.0.1", "ip", "logs", "2026-10-01T00:00:00Z"),
        _obs("10.0.0.1", "ip", "network", "2026-10-03T11:00:00Z"),
    ]
    score, _components, links = scoring_mod.score_pivot(
        Entity("10.0.0.1", "ip"), obs, ["logs", "network"], 60, {}, now=now
    )
    # 20 sources + 0 verdict + 0 temporal (2 days apart, 60s window) + 10 recency
    assert score == 30
    assert links == []


def test_score_caps_at_100():
    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    ts = "2026-10-03T11:59:00Z"
    obs = [
        _obs("x", "ip", s, ts) for s in ("logs", "network", "files", "findings", "logs")
    ]
    score, _components, _links = scoring_mod.score_pivot(
        Entity("x", "ip"),
        obs,
        ["logs", "network", "files", "findings"],
        3600,
        {("ip", "x"): "malicious"},
        now=now,
    )
    assert score == 80  # 40 (cap) + 20 + 10 + 10


def test_temporal_window_boundary():
    obs = [
        _obs("a", "ip", "logs", "2026-10-03T10:00:00Z"),
        _obs("a", "ip", "network", "2026-10-03T11:00:01Z"),
    ]
    assert scoring_mod.find_temporal_links(obs, 3600) == []
    assert len(scoring_mod.find_temporal_links(obs, 3601)) == 1
    # Same source type never links.
    same = [
        _obs("a", "ip", "logs", "2026-10-03T10:00:00Z"),
        _obs("a", "ip", "logs", "2026-10-03T10:00:10Z"),
    ]
    assert scoring_mod.find_temporal_links(same, 3600) == []


def test_format_window():
    assert scoring_mod.format_window(30) == "30s"
    assert scoring_mod.format_window(90) == "1m30s"
    assert scoring_mod.format_window(3600) == "1h"
    assert scoring_mod.format_window(5400) == "1h30m"
    assert scoring_mod.format_window(90000) == "1d1h"


def test_detect_pivots_min_sources_and_order():
    graph = graph_mod.build_graph(
        [
            _obs("10.0.0.1", "ip", "logs", "2026-10-03T10:00:00Z"),
            _obs("10.0.0.1", "ip", "network", "2026-10-03T10:00:05Z"),
            _obs("10.0.0.2", "ip", "logs", "2026-10-03T10:00:00Z"),
            _obs("example.com", "domain", "logs", "2026-10-03T10:00:00Z"),
            _obs("example.com", "domain", "network", "2026-10-03T10:00:05Z"),
            _obs("example.com", "domain", "findings", "2026-10-03T10:00:05Z"),
        ],
        [],
    )
    pivots = scoring_mod.detect_pivots(graph, min_sources=2, window_seconds=3600)
    assert [p.entity.value for p in pivots] == ["example.com", "10.0.0.1"]
    assert pivots[0].score >= pivots[1].score  # more sources ranks first
    assert all(p.evidence_refs() for p in pivots)  # evidence-backed invariant
    pivots3 = scoring_mod.detect_pivots(graph, min_sources=3, window_seconds=3600)
    assert [p.entity.value for p in pivots3] == ["example.com"]


# ---------------------------------------------------------------------------
# Verdict maps
# ---------------------------------------------------------------------------


def test_verdict_maps_strongest_and_conflicting():
    from aegisforge.intel.models import IntelRecord

    records = [
        IntelRecord(
            indicator="203.0.113.7",
            indicator_type="ip",
            provider="a",
            verdict="clean",
        ),
        IntelRecord(
            indicator="203.0.113.7",
            indicator_type="ip",
            provider="b",
            verdict="malicious",
        ),
        IntelRecord(
            indicator="10.0.0.1",
            indicator_type="ip",
            provider="a",
            verdict="suspicious",
            skipped=True,
        ),
    ]
    score_v, display_v = engine_mod.verdict_maps(records)
    assert score_v[("ip", "203.0.113.7")] == "malicious"
    assert display_v[("ip", "203.0.113.7")] == "conflicting"
    assert ("ip", "10.0.0.1") not in score_v  # skipped records ignored


# ---------------------------------------------------------------------------
# Engine: extraction from a real case
# ---------------------------------------------------------------------------


def test_extract_observations_from_case(cases_home: Path):
    case_id = _make_case(cases_home)
    from aegisforge.cases.store import load_case

    case = load_case(case_id)
    observations, edges, warnings = extract_mod.extract_observations(case)
    assert warnings == []
    by_key: dict[tuple[str, str], list[Observation]] = {}
    for obs in observations:
        by_key.setdefault(obs.entity.key(), []).append(obs)
    assert ("ip", "203.0.113.7") in by_key
    assert ("user", "root") in by_key
    assert ("hostname", "web") in by_key
    # The IP appears in both logs and findings evidence.
    sources = {o.source_type for o in by_key[("ip", "203.0.113.7")]}
    assert sources == {"logs", "findings"}
    assert edges, "co-occurrence edges expected from log lines"
    assert all(e.evidence_refs for e in edges)


def test_correlate_case_end_to_end(cases_home: Path):
    case_id = _make_case(cases_home)
    from aegisforge.cases.store import load_case

    case = load_case(case_id)
    result = engine_mod.correlate_case(case, window_seconds=3600, min_sources=2)
    assert result.case_id == case_id
    assert len(result.entities) >= 3
    pivots = {p.entity.key(): p for p in result.pivots}
    assert ("ip", "203.0.113.7") in pivots
    pivot = pivots[("ip", "203.0.113.7")]
    assert pivot.score == 40  # 20 sources + 0 verdict + 10 temporal + 10 recency
    assert pivot.evidence_refs()


def test_correlate_case_with_fake_intel(cases_home: Path):
    from aegisforge.cases.store import load_case
    from aegisforge.intel.models import IntelRecord

    case_id = _make_case(cases_home)
    case = load_case(case_id)

    class FakeEnrichment:
        records = [
            IntelRecord(
                indicator="203.0.113.7",
                indicator_type="ip",
                provider="test",
                verdict="malicious",
                confidence=90,
            )
        ]

    result = engine_mod.correlate_case(
        case,
        window_seconds=3600,
        min_sources=2,
        intel_lookup=lambda inds: FakeEnrichment(),
    )
    assert result.enriched is True
    pivot = next(p for p in result.pivots if p.entity.key() == ("ip", "203.0.113.7"))
    assert pivot.score == 60  # 20 sources + 20 malicious + 10 temporal + 10 recency
    assert pivot.verdict == "malicious"


def test_correlate_case_read_only(cases_home: Path):
    case_id = _make_case(cases_home)
    from aegisforge.cases.store import case_dir, load_case

    case = load_case(case_id)
    before: dict[str, str] = {}
    for path in sorted(case_dir(case_id).rglob("*")):
        if path.is_file():
            before[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    engine_mod.correlate_case(case, window_seconds=3600, min_sources=2)
    after = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((case_dir(case_id)).rglob("*"))
        if path.is_file()
    }
    assert before == after, "correlation must not modify the case store"


# ---------------------------------------------------------------------------
# Incident timeline
# ---------------------------------------------------------------------------


def test_incident_timeline_merges_and_highlights(cases_home: Path):
    case_id = _make_case(cases_home)
    from aegisforge.cases.store import load_case

    case = load_case(case_id)
    result = engine_mod.correlate_case(case, window_seconds=3600, min_sources=2)
    timed, untimed = timeline_mod.build_incident_timeline(case, result.pivots)
    pivot_entries = [e for e in timed if e.pivot]
    assert len(pivot_entries) == len(result.pivots) >= 1
    entry = pivot_entries[0]
    assert entry.evidence_refs, "pivot entries must be evidence-backed"
    assert entry.pivot_score is not None
    # Chronological order holds across merged entries.
    stamps = [e.timestamp for e in timed if e.timestamp]
    assert stamps == sorted(stamps)
    d = timeline_mod.incident_timeline_to_dict(timed, untimed)
    assert d["pivot_count"] == len(pivot_entries)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_entities(cases_home: Path):
    case_id = _make_case(cases_home)
    code, out = _run_cli(["correlate", "entities", "--case", case_id])
    assert code == 0
    assert "203.0.113.7" in out
    code, out = _run_cli(["correlate", "entities", "--case", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    assert data["entity_count"] >= 3
    code, out = _run_cli(["correlate", "entities", "--case", case_id, "--csv"])
    assert code == 0
    assert out.splitlines()[0] == "type,value,observations,source_types,evidence_refs"


def test_cli_run(cases_home: Path):
    case_id = _make_case(cases_home)
    code, out = _run_cli(["correlate", "run", "--case", case_id, "--explain"])
    assert code == 0
    assert "Pivots (1)" in out
    assert "Score formula" in out
    code, out = _run_cli(["correlate", "run", "--case", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    assert data["pivot_count"] == 1
    assert data["pivots"][0]["score"] == 40
    code, out = _run_cli(["correlate", "run", "--case", case_id, "--csv"])
    assert code == 0
    assert out.splitlines()[0].startswith("type,value,score")


def test_cli_run_min_sources_filters(cases_home: Path):
    case_id = _make_case(cases_home)
    code, out = _run_cli(
        ["correlate", "run", "--case", case_id, "--min-sources", "3", "--json"]
    )
    assert code == 0
    assert json.loads(out)["data"]["pivot_count"] == 0


def test_cli_run_bad_window(cases_home: Path):
    case_id = _make_case(cases_home)
    code, out = _run_cli(["correlate", "run", "--case", case_id, "--window", "bogus"])
    assert code == 2


def test_cli_run_unknown_case(cases_home: Path):
    code, _out = _run_cli(["correlate", "run", "--case", "CASE-2099-999"])
    assert code == 2


def test_cli_timeline(cases_home: Path):
    case_id = _make_case(cases_home)
    code, out = _run_cli(["correlate", "timeline", "--case", case_id])
    assert code == 0
    assert ">>>" in out  # pivot highlight
    code, out = _run_cli(["correlate", "timeline", "--case", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    assert data["pivot_count"] >= 1


def test_cli_finding_for_malicious_pivot(cases_home: Path, tmp_path: Path):
    case_id = _make_case(cases_home)
    blocklist = tmp_path / "block.csv"
    blocklist.write_text(
        "indicator,type,source,confidence,note\n203.0.113.7,ip,test,90,smoke\n",
        encoding="utf-8",
    )
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps(
            {
                "intel_blocklist": str(blocklist),
                "intel_providers": ["local-blocklist"],
                "correlate_pivot_threshold": 60,
            }
        ),
        encoding="utf-8",
    )
    code, out = _run_cli(
        ["--config", str(cfg), "correlate", "run", "--case", case_id, "--json"]
    )
    assert code == 1  # malicious pivot -> high finding -> exit 1
    data = json.loads(out)
    assert any(
        f["severity"] == "high" and "Correlation pivot" in f["title"]
        for f in data["findings"]
    )
    reason = next(
        f["reason"] for f in data["findings"] if "Correlation pivot" in f["title"]
    )
    assert "OBSERVED" in reason and "INFERRED" in reason


def test_plugin_registered():
    info = get_registry().get("correlate")
    assert info.version == "0.9.0"
    assert "correlate run" in info.commands


# ---------------------------------------------------------------------------
# Synthetic pcap builder (minimal: DNS query over UDP/IPv4)
# ---------------------------------------------------------------------------


def _build_pcap(packets: list[bytes]) -> bytes:
    out = _struct.pack(">I", 0xA1B2C3D4)
    out += _struct.pack(">HHIIII", 2, 4, 0, 0, 65535, 1)
    for i, pkt in enumerate(packets):
        out += _struct.pack(">IIII", 1_700_000_000 + i, 0, len(pkt), len(pkt)) + pkt
    return out


def _dns_query_packet(name: str = "evil.example.com") -> bytes:
    eth = b"\x00" * 6 + b"\x11" * 6 + _struct.pack(">H", 0x0800)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    dns = (
        _struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + qname
        + _struct.pack(">HH", 1, 1)
    )
    udp = _struct.pack(">HHHH", 5353, 53, 8 + len(dns), 0) + dns
    src = bytes([203, 0, 113, 7])
    dst = bytes([8, 8, 8, 8])
    ip = (
        _struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
        + src
        + dst
        + udp
    )
    return eth + ip


def test_extract_pcap_indicators(cases_home: Path):
    case_id = _make_case(cases_home)
    pcap_path = cases_home / "capture.pcap"
    pcap_path.write_bytes(_build_pcap([_dns_query_packet()]))
    code, _ = _run_cli(
        ["case", "attach", case_id, "--kind", "network", "--source", str(pcap_path)]
    )
    assert code == 0
    from aegisforge.cases.store import load_case

    case = load_case(case_id)
    observations, edges, warnings = extract_mod.extract_observations(case)
    assert warnings == []
    by_key = {(o.entity.type, o.entity.value): o for o in observations}
    # DNS query name becomes a domain observation from the network source.
    assert ("domain", "evil.example.com") in by_key
    assert by_key[("domain", "evil.example.com")].source_type == "network"
    # The packet's source IP is observed in both logs and pcap -> pivot.
    from aegisforge.correlate import engine as engine_mod

    result = engine_mod.correlate_case(case, window_seconds=3600, min_sources=2)
    pivot = next(p for p in result.pivots if p.entity.key() == ("ip", "203.0.113.7"))
    assert set(pivot.source_types) >= {"logs", "findings", "network"}
    assert pivot.score >= 30  # 3 sources = 30 + temporal + recency


def test_extract_log_urls_and_domains(cases_home: Path):
    case_id = _make_case(cases_home)
    log = cases_home / "proxy.log"
    log.write_text(
        "Oct  3 02:12:00 web squid[9]: GET https://evil.example.com/login "
        "from 10.0.0.9\n",
        encoding="utf-8",
    )
    code, _ = _run_cli(
        ["case", "attach", case_id, "--kind", "logs", "--source", str(log)]
    )
    assert code == 0
    from aegisforge.cases.store import load_case

    case = load_case(case_id)
    observations, _edges, _warnings = extract_mod.extract_observations(case)
    keys = {o.entity.key() for o in observations}
    # The URL's host is extracted as a domain; the client IP as an ip.
    assert ("domain", "evil.example.com") in keys
    assert ("ip", "10.0.0.9") in keys
