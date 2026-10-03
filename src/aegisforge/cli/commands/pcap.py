"""Offline PCAP analysis command implementations."""

from __future__ import annotations

import argparse
import os

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.results import Result
from aegisforge.pcap import analyze as pcap_analyze_mod
from aegisforge.pcap.analyze import AnalyzeOptions as PcapAnalyzeOptions
from aegisforge.pcap.reader import PcapError

from .shared import _hist_lines


def _pcap_options(args: argparse.Namespace, cfg: AppConfig) -> PcapAnalyzeOptions:
    return PcapAnalyzeOptions(
        burst_window=int(cfg["pcap_burst_window"]),
        burst_threshold=int(cfg["pcap_burst_threshold"]),
        unusual_port_packets=int(cfg["pcap_unusual_port_packets"]),
        top=args.top if getattr(args, "top", None) else int(cfg["pcap_top_n"]),
    )


def _pcap_check(path: str) -> str | None:
    if not os.path.exists(path):
        return f"file does not exist: {path}"
    if not os.path.isfile(path):
        return f"not a file: {path}"
    if not os.access(path, os.R_OK):
        return f"file is not readable: {path}"
    return None


def cmd_pcap_summary(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap summary", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        summary = pcap_analyze_mod.summarize(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = summary.to_dict()
    data["pcap_talkers"] = [
        {"ip": ip, "packets": count} for ip, count in data["top_talkers_packets"]
    ]
    result.data = data
    for finding in summary.findings:
        result.add_finding(finding)
    result.summary = (
        f"{args.file}: {summary.packet_count} packet(s), "
        f"{summary.total_bytes} bytes, {len(summary.findings)} finding(s), "
        f"{summary.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.analysis.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "packets": summary.packet_count,
                "bytes": summary.total_bytes,
                "warnings": summary.warning_count,
                "findings": len(summary.findings),
            },
        )
    )
    return result


def cmd_pcap_conversations(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap conversations", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        conv = pcap_analyze_mod.conversations(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = conv.to_dict()
    data["pcap_flows"] = data.pop("flows")
    result.data = data
    result.summary = (
        f"{args.file}: {len(conv.flows)} conversation(s) shown, "
        f"{conv.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.conversations.completed",
            source="aegisforge",
            evidence={"file": args.file, "flows_shown": len(conv.flows)},
        )
    )
    return result


def cmd_pcap_dns(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap dns", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        dns = pcap_analyze_mod.dns_activity(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = dns.to_dict()
    data["pcap_dns"] = data.pop("queries")
    result.data = data
    result.summary = (
        f"{args.file}: {len(dns.queries)} queried name(s), "
        f"{dns.malformed_count} malformed, {dns.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.dns.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "names": len(dns.queries),
                "malformed": dns.malformed_count,
            },
        )
    )
    return result


def cmd_pcap_http(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap http", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        http = pcap_analyze_mod.http_metadata(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = http.to_dict()
    data["pcap_http"] = data.pop("records")
    result.data = data
    result.summary = (
        f"{args.file}: {len(http.records)} HTTP record(s), "
        f"{http.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.http.completed",
            source="aegisforge",
            evidence={"file": args.file, "records": len(http.records)},
        )
    )
    return result


def cmd_pcap_tls(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap tls", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        tls = pcap_analyze_mod.tls_metadata(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = tls.to_dict()
    data["pcap_tls"] = data.pop("records")
    result.data = data
    result.summary = (
        f"{args.file}: {len(tls.records)} TLS ClientHello(s), "
        f"{tls.failed_count} unparsable, {tls.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.tls.completed",
            source="aegisforge",
            evidence={"file": args.file, "records": len(tls.records)},
        )
    )
    return result


def cmd_pcap_indicators(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap indicators", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        ind = pcap_analyze_mod.extract_indicators(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = ind.to_dict()
    data["pcap_indicators"] = data.pop("indicators")
    result.data = data
    result.summary = (
        f"{args.file}: {len(ind.indicators)} observed indicator(s), "
        f"{ind.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="pcap.indicators.completed",
            source="aegisforge",
            evidence={"file": args.file, "indicators": len(ind.indicators)},
        )
    )
    return result


def cmd_pcap_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="pcap timeline", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        tl = pcap_analyze_mod.timeline(args.file, _pcap_options(args, cfg))
    except PcapError as exc:
        result.fail(str(exc))
        return result
    data = tl.to_dict()
    data["pcap_timeline"] = data.pop("events")
    result.data = data
    for entry in tl.events:
        result.add_event(
            Event(
                event_type=f"pcap.{entry.kind.replace('-', '.')}",
                source="pcap",
                severity=entry.severity,
                timestamp=entry.timestamp,
                evidence={"summary": entry.summary, "file": args.file},
            )
        )
    result.summary = (
        f"{args.file}: {len(tl.events)} timeline event(s), "
        f"{tl.warning_count} warning(s)"
    )
    return result


def render_pcap_summary(result: Result) -> str:
    """Human-readable rendering of a `pcap summary` result."""
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        f"Packets: {data.get('packet_count')}  "
        f"Bytes: {data.get('total_bytes')}  "
        f"Range: {data.get('time_first')} .. {data.get('time_last')}"
    )
    lines.append("")
    lines.extend(_hist_lines("Protocols", data.get("protocol_histogram", [])))
    lines.append("")
    lines.extend(
        _hist_lines("Top talkers (packets)", data.get("top_talkers_packets", []))
    )
    lines.append("")
    lines.extend(_hist_lines("Top talkers (bytes)", data.get("top_talkers_bytes", [])))
    lines.append("")
    lines.extend(_hist_lines("Top ports", data.get("top_ports", [])))
    unusual = data.get("unusual_ports", [])
    if unusual:
        lines.append("")
        lines.append("Unusual ports (observed — not a verdict):")
        for entry in unusual:
            lines.append(
                f"  {entry.get('protocol')}/{entry.get('port')}: "
                f"{entry.get('packets')} packets"
            )
    if data.get("warnings"):
        lines.append("")
        lines.append(f"Warnings ({data.get('warning_count')}):")
        for w in data["warnings"][:5]:
            lines.append(f"  {w.get('reason')}")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def render_pcap_conversations(result: Result) -> str:
    """Human-readable rendering of a `pcap conversations` result."""
    data = result.data
    flows = data.get("pcap_flows", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(
        f"{'SOURCE':<22}{'DEST':<22}{'PROTO':<6}{'SPORT':<7}{'DPORT':<7}"
        f"{'PKTS':<7}{'BYTES':<9}DURATION"
    )
    for f in flows:
        lines.append(
            f"{str(f.get('src_ip')):<22}{str(f.get('dst_ip')):<22}"
            f"{str(f.get('protocol')):<6}{str(f.get('src_port')):<7}"
            f"{str(f.get('dst_port')):<7}{f.get('packets'):<7}"
            f"{f.get('bytes'):<9}{f.get('duration_s')}s"
        )
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
    return "\n".join(lines)


def render_pcap_dns(result: Result) -> str:
    """Human-readable rendering of a `pcap dns` result."""
    data = result.data
    queries = data.get("pcap_dns", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'NAME':<40}{'QTYPE':<8}{'Q':<6}{'RESP':<6}NXDOMAIN")
    for q in queries:
        lines.append(
            f"{str(q.get('name'))[:39]:<40}{str(q.get('qtype')):<8}"
            f"{q.get('queries'):<6}{q.get('responses'):<6}{q.get('nxdomain')}"
        )
    return "\n".join(lines)


def render_pcap_http(result: Result) -> str:
    """Human-readable rendering of a `pcap http` result."""
    data = result.data
    records = data.get("pcap_http", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    for r in records:
        if r.get("method"):
            lines.append(
                f"  {r.get('timestamp')} {r.get('src')} -> {r.get('dst')}: "
                f"{r.get('method')} {r.get('host')}{r.get('path')}"
            )
        else:
            lines.append(
                f"  {r.get('timestamp')} {r.get('src')} -> {r.get('dst')}: "
                f"HTTP {r.get('status')}"
            )
    return "\n".join(lines)


def render_pcap_tls(result: Result) -> str:
    """Human-readable rendering of a `pcap tls` result."""
    data = result.data
    records = data.get("pcap_tls", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'TIMESTAMP':<28}{'SOURCE':<18}{'SNI':<36}VERSION")
    for r in records:
        lines.append(
            f"{str(r.get('timestamp')):<28}{str(r.get('src')):<18}"
            f"{str(r.get('sni') or '(none)')[:35]:<36}{r.get('offered_version')}"
        )
    return "\n".join(lines)


def render_pcap_indicators(result: Result) -> str:
    """Human-readable rendering of a `pcap indicators` result."""
    data = result.data
    indicators = data.get("pcap_indicators", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append("Observed in capture (not a verdict):")
    lines.append(f"{'TYPE':<8}{'VALUE':<44}FIRST SEEN")
    for i in indicators:
        lines.append(
            f"{str(i.get('itype')):<8}{str(i.get('value'))[:43]:<44}"
            f"{i.get('first_seen')}"
        )
    return "\n".join(lines)


def render_pcap_timeline(result: Result) -> str:
    """Human-readable rendering of a `pcap timeline` result."""
    data = result.data
    events = data.get("pcap_timeline", [])
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"{'TIMESTAMP (UTC)':<28}{'KIND':<12}SUMMARY")
    for e in events[:50]:
        lines.append(
            f"{str(e.get('timestamp')):<28}{str(e.get('kind')):<12}"
            f"{str(e.get('summary'))[:80]}"
        )
    if len(events) > 50:
        lines.append(f"  ... and {len(events) - 50} more events")
    return "\n".join(lines)
