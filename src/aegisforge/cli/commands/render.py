"""Result rendering: human-readable, JSON and CSV output."""

from __future__ import annotations

import argparse
import csv
import io
import json
from typing import Any

from aegisforge.core.events import Event
from aegisforge.core.findings import Finding
from aegisforge.core.results import Result
from aegisforge.logs import redact as logs_redact_mod

from .case import (
    render_case_attach,
    render_case_create,
    render_case_finding,
    render_case_findings,
    render_case_link,
    render_case_list,
    render_case_note,
    render_case_report,
    render_case_show,
    render_case_status,
    render_case_timeline,
)
from .correlate import (
    render_correlate_entities,
    render_correlate_run,
    render_correlate_timeline,
)
from .forensics import (
    render_forensics_duplicates,
    render_forensics_inventory,
    render_forensics_manifest,
    render_forensics_timeline,
    render_forensics_verify,
)
from .intel import (
    render_intel_cache_clear,
    render_intel_correlate,
    render_intel_lookup,
    render_intel_providers,
)
from .logs import render_logs_analyze
from .pcap import (
    render_pcap_conversations,
    render_pcap_dns,
    render_pcap_http,
    render_pcap_indicators,
    render_pcap_summary,
    render_pcap_timeline,
    render_pcap_tls,
)
from .report import render_report


def _kv_lines(data: dict[str, Any], indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.extend(_kv_lines(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{pad}{key}: ({len(value)} items)")
            for item in value[:20]:
                if isinstance(item, dict):
                    lines.append(
                        f"{pad}  - " + ", ".join(f"{k}={v}" for k, v in item.items())
                    )
                else:
                    lines.append(f"{pad}  - {item}")
            if len(value) > 20:
                lines.append(f"{pad}  ... and {len(value) - 20} more")
        else:
            lines.append(f"{pad}{key}: {value}")
    return lines


def render_human(result: Result) -> str:
    lines = [result.summary] if result.summary else []
    if result.status == "error":
        return "\n".join(lines) if lines else "error"
    data = dict(result.data)
    data.pop("events", None)
    ports = data.pop("ports", None)
    changes = data.pop("changes", None)
    baselines = data.pop("baselines", None)
    if data:
        lines.append("")
        lines.extend(_kv_lines(data))
    if isinstance(ports, list):
        lines.append("")
        lines.append(f"{'PORT':<7}{'STATE':<10}{'SERVICE':<12}BANNER")
        for p in ports:
            banner = (p.get("banner") or "")[:64]
            lines.append(
                f"{p.get('port'):<7}{p.get('state'):<10}"
                f"{(p.get('service') or ''):<12}{banner}"
            )
    if isinstance(changes, list):
        lines.append("")
        for change in ("new", "closed", "changed"):
            group = [c for c in changes if c.get("change") == change]
            if group:
                lines.append(f"{change.upper()}:")
                for c in group:
                    lines.append(f"  {c.get('port')}: {c.get('detail')}")
    if isinstance(baselines, list):
        lines.append("")
        lines.append(f"{'NAME':<24}{'TARGET':<20}{'OPEN':<6}CREATED")
        for b in baselines:
            lines.append(
                f"{str(b.get('name')):<24}{str(b.get('target')):<20}"
                f"{str(b.get('ports_open')):<6}{b.get('created')}"
            )
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def _csv_rows(result: Result) -> tuple[list[str], list[list[Any]]]:
    """Flatten the primary list in result.data to CSV rows."""
    data = result.data
    if "results" in data:  # ping
        rows = data["results"]
        headers = [
            "target",
            "reachable",
            "transmitted",
            "received",
            "loss_percent",
            "rtt_min_ms",
            "rtt_avg_ms",
            "rtt_max_ms",
            "error",
        ]
    elif "hops" in data:  # trace
        rows = data["hops"]
        headers = ["hop", "ip", "hostname", "rtt_ms"]
    elif "interfaces" in data:  # interfaces / inventory
        rows = data["interfaces"]
        headers = ["name", "mac", "mtu", "status", "ipv4", "ipv6"]
    elif "hosts" in data:  # subnet expand
        rows = [{"host": h} for h in data["hosts"]]
        headers = ["host"]
    elif "ports" in data:  # scan
        rows = [
            {
                "target": data.get("target", ""),
                "port": p.get("port"),
                "state": p.get("state"),
                "service": p.get("service"),
                "rtt_ms": p.get("rtt_ms"),
                "banner": p.get("banner"),
            }
            for p in data["ports"]
        ]
        headers = ["target", "port", "state", "service", "rtt_ms", "banner"]
    elif "changes" in data:  # baseline diff
        rows = data["changes"]
        headers = ["port", "change", "detail"]
    elif "baselines" in data:  # baseline list
        rows = data["baselines"]
        headers = ["name", "target", "ports_scanned", "ports_open", "created"]
    elif "addresses" in data:  # dns
        rows = data["addresses"]
        headers = ["ip", "family"]
    elif "records" in data:  # domain dns
        rows = data["records"]
        headers = ["name", "rtype", "ttl", "detail"]
    elif "log_events" in data:  # logs analyze
        rows = data["log_events"]
        headers = ["line_number", "timestamp", "parser", "host", "severity", "message"]
    elif "files" in data:  # forensics inventory
        rows = [
            {
                "path": f.get("path"),
                "size": f.get("size"),
                "mtime": f.get("mtime"),
                "sha256": (f.get("hashes") or {}).get("sha256"),
                "md5": (f.get("hashes") or {}).get("md5"),
                "sha1": (f.get("hashes") or {}).get("sha1"),
                "file_type": f.get("file_type"),
                "type_source": f.get("type_source"),
            }
            for f in data["files"]
        ]
        headers = [
            "path",
            "size",
            "mtime",
            "sha256",
            "md5",
            "sha1",
            "file_type",
            "type_source",
        ]
    elif "timeline" in data:  # forensics timeline
        rows = data["timeline"]
        headers = ["timestamp", "kind", "path"]
    elif "groups" in data:  # forensics duplicates
        rows = [
            {"sha256": g.get("sha256"), "path": p}
            for g in data["groups"]
            for p in g.get("paths", [])
        ]
        headers = ["sha256", "path"]
    elif "changed" in data:  # forensics verify
        rows = [
            {"status": status, "path": c.get("path"), "detail": c.get("detail")}
            for status, key in (
                ("changed", "changed"),
                ("missing", "missing"),
                ("new", "new"),
            )
            for c in data.get(key, [])
        ]
        headers = ["status", "path", "detail"]
    elif "timeline_entries" in data:  # case timeline
        rows = data["timeline_entries"]
        headers = ["timestamp", "source", "kind", "summary", "detail"]
    elif "pcap_talkers" in data:  # pcap summary
        rows = data["pcap_talkers"]
        headers = ["ip", "packets"]
    elif "pcap_flows" in data:  # pcap conversations
        rows = data["pcap_flows"]
        headers = [
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "packets",
            "bytes",
            "duration_s",
            "tcp_flags",
        ]
    elif "pcap_dns" in data:  # pcap dns
        rows = data["pcap_dns"]
        headers = ["name", "qtype", "queries", "responses", "nxdomain"]
    elif "pcap_http" in data:  # pcap http
        rows = data["pcap_http"]
        headers = ["timestamp", "src", "dst", "method", "host", "path", "status"]
    elif "pcap_tls" in data:  # pcap tls
        rows = data["pcap_tls"]
        headers = ["timestamp", "src", "dst", "sni", "offered_version"]
    elif "pcap_indicators" in data:  # pcap indicators
        rows = data["pcap_indicators"]
        headers = ["itype", "value", "first_seen", "last_seen", "observation"]
    elif "pcap_timeline" in data:  # pcap timeline
        rows = data["pcap_timeline"]
        headers = ["timestamp", "source", "kind", "summary"]
    elif "intel_rows" in data:  # intel correlate
        rows = [
            {
                "indicator": r.get("indicator"),
                "type": r.get("indicator_type"),
                "combined_verdict": r.get("combined_verdict"),
                "providers": ";".join(r.get("providers_hit", [])),
                "local_evidence": ";".join(r.get("local_evidence", [])),
            }
            for r in data["intel_rows"]
        ]
        headers = [
            "indicator",
            "type",
            "combined_verdict",
            "providers",
            "local_evidence",
        ]
    elif "intel_records" in data:  # intel lookup
        rows = [
            {
                "indicator": r.get("indicator"),
                "type": r.get("indicator_type"),
                "provider": r.get("provider"),
                "verdict": r.get("verdict_label", r.get("verdict")),
                "confidence": r.get("confidence"),
                "skipped": r.get("skipped"),
                "detail": r.get("detail"),
            }
            for r in data["intel_records"]
        ]
        headers = [
            "indicator",
            "type",
            "provider",
            "verdict",
            "confidence",
            "skipped",
            "detail",
        ]
    elif "case_findings" in data:  # case findings
        rows = [
            {
                "finding_id": f.get("finding_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
                "indicators": ";".join(
                    f"{i.get('value')}({i.get('type')})"
                    for i in f.get("indicators", [])
                ),
            }
            for f in data["case_findings"]
        ]
        headers = [
            "finding_id",
            "title",
            "severity",
            "confidence",
            "status",
            "indicators",
        ]
    elif "pivots" in data:  # correlate run
        rows = [
            {
                "type": (p.get("entity") or {}).get("type"),
                "value": (p.get("entity") or {}).get("value"),
                "score": p.get("score"),
                "sources": ";".join(p.get("source_types", [])),
                "verdict": p.get("verdict"),
                "evidence_refs": ";".join(p.get("evidence_refs", [])),
            }
            for p in data["pivots"]
        ]
        headers = ["type", "value", "score", "sources", "verdict", "evidence_refs"]
    elif "entities" in data:  # correlate entities
        rows = data["entities"]
        headers = ["type", "value", "observations", "source_types", "evidence_refs"]
    else:
        rows = [data]
        headers = sorted(data.keys())
    table = [[row.get(h, "") for h in headers] for row in rows]
    # Flatten list values for CSV cells.
    table = [
        [(";".join(map(str, c)) if isinstance(c, list) else c) for c in row]
        for row in table
    ]
    return headers, table


def _redacted_result(result: Result) -> Result:
    """Copy of *result* with IPs/emails masked (output only, never source)."""
    redacted = Result(
        command=result.command,
        target=(logs_redact_mod.redact_text(result.target) if result.target else None),
        status=result.status,
        summary=logs_redact_mod.redact_text(result.summary),
        data=logs_redact_mod.redact_value(result.data),
        tool=result.tool,
        version=result.version,
        timestamp=result.timestamp,
    )
    for finding in result.findings:
        redacted.findings.append(
            Finding(**logs_redact_mod.redact_value(finding.to_dict()))
        )
    for event in result.events:
        redacted.events.append(Event(**logs_redact_mod.redact_value(event.to_dict())))
    return redacted


def render_version(result: Result) -> str:
    lines = [f"aegisforge {result.data.get('version')}", "", "modules:"]
    for name, version in (result.data.get("modules") or {}).items():
        lines.append(f"  {name}: {version}")
    return "\n".join(lines)


def render(result: Result, args: argparse.Namespace) -> str:
    if getattr(args, "redact", False) and result.command.startswith("logs "):
        result = _redacted_result(result)
    if result.command == "logs analyze" and not args.json and not args.csv:
        return render_logs_analyze(result)
    if result.command.startswith("forensics ") and not args.json and not args.csv:
        renderer = {
            "forensics inventory": render_forensics_inventory,
            "forensics manifest": render_forensics_manifest,
            "forensics verify": render_forensics_verify,
            "forensics duplicates": render_forensics_duplicates,
            "forensics timeline": render_forensics_timeline,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("case ") and not args.json and not args.csv:
        renderer = {
            "case create": render_case_create,
            "case list": render_case_list,
            "case show": render_case_show,
            "case attach": render_case_attach,
            "case timeline": render_case_timeline,
            "case finding": render_case_finding,
            "case findings": render_case_findings,
            "case link": render_case_link,
            "case note": render_case_note,
            "case report": render_case_report,
            "case status": render_case_status,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("pcap ") and not args.json and not args.csv:
        renderer = {
            "pcap summary": render_pcap_summary,
            "pcap conversations": render_pcap_conversations,
            "pcap dns": render_pcap_dns,
            "pcap http": render_pcap_http,
            "pcap tls": render_pcap_tls,
            "pcap indicators": render_pcap_indicators,
            "pcap timeline": render_pcap_timeline,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("intel ") and not args.json and not args.csv:
        renderer = {
            "intel lookup": render_intel_lookup,
            "intel correlate": render_intel_correlate,
            "intel providers": render_intel_providers,
            "intel cache-clear": render_intel_cache_clear,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("correlate ") and not args.json and not args.csv:
        renderer = {
            "correlate run": render_correlate_run,
            "correlate entities": render_correlate_entities,
            "correlate timeline": render_correlate_timeline,
        }.get(result.command)
        if renderer is not None:
            return renderer(result)
    if result.command.startswith("report ") and not args.json and not args.csv:
        return render_report(result)
    if result.command == "version" and not args.json and not args.csv:
        return render_version(result)
    if args.json:
        return json.dumps(result.to_dict(), indent=2)
    if args.csv:
        headers, rows = _csv_rows(result)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        writer.writerows(rows)
        return buf.getvalue().rstrip("\n")
    return render_human(result)
