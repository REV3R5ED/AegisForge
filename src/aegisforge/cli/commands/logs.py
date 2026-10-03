"""Log analysis command implementations."""

from __future__ import annotations

import argparse

from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.results import Result
from aegisforge.logs import analyze as logs_analyze_mod
from aegisforge.logs import detect as logs_detect_mod
from aegisforge.logs.analyze import AnalyzeOptions
from aegisforge.logs.filters import LogFilter
from aegisforge.logs.models import PARSER_UNKNOWN
from aegisforge.network.validation import ValidationError

from .shared import _hist_lines


def cmd_logs_detect(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="logs detect", target=args.file)
    try:
        detection = logs_detect_mod.detect_file(args.file)
    except OSError as exc:
        result.fail(f"cannot read {args.file}: {exc}")
        return result
    result.data = {"file": args.file, **detection.to_dict()}
    if detection.parser == PARSER_UNKNOWN:
        result.summary = (
            f"{args.file}: log format unknown "
            f"(best score {detection.confidence:.2f}); pass --format explicitly"
        )
    else:
        result.summary = (
            f"{args.file}: detected {detection.parser} format "
            f"(confidence {detection.confidence:.2f})"
        )
    result.add_event(
        Event(
            event_type="logs.format.detected",
            source="aegisforge",
            evidence={
                "file": args.file,
                "parser": detection.parser,
                "confidence": round(detection.confidence, 3),
            },
        )
    )
    return result


def cmd_logs_analyze(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="logs analyze", target=args.file)
    try:
        filt = LogFilter(
            since=args.since,
            until=args.until,
            levels=tuple(args.level or ()),
            contains=tuple(args.contains or ()),
            not_contains=tuple(args.not_contains or ()),
            host=args.host,
            limit=args.limit,
        )
        options = AnalyzeOptions(
            parser_name=args.format,
            burst_window=(
                args.burst_window
                if args.burst_window is not None
                else cfg["logs_burst_window"]
            ),
            burst_threshold=(
                args.burst_threshold
                if args.burst_threshold is not None
                else cfg["logs_burst_threshold"]
            ),
            context_lines=(
                args.context if args.context is not None else cfg["logs_context_lines"]
            ),
        )
        analysis = logs_analyze_mod.analyze_file(args.file, filt, options)
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    data = analysis.to_dict()
    # Rename for the CSV renderer (primary table = the matched events).
    data["log_events"] = data.pop("events")
    data["filters"] = filt.describe()
    data["redacted"] = bool(args.redact)
    result.data = data
    for finding in analysis.findings:
        result.add_finding(finding)
    result.summary = (
        f"{args.file}: {analysis.events_matched} event(s) matched "
        f"({analysis.parser}), {len(analysis.findings)} finding(s), "
        f"{analysis.warning_count} warning(s)"
    )
    result.add_event(
        Event(
            event_type="logs.analysis.completed",
            source="aegisforge",
            evidence={
                "file": args.file,
                "parser": analysis.parser,
                "events_matched": analysis.events_matched,
                "warnings": analysis.warning_count,
                "findings": len(analysis.findings),
            },
        )
    )
    return result


def render_logs_analyze(result: Result) -> str:
    """Human-readable rendering of a `logs analyze` result envelope."""
    data = result.data
    lines = [result.summary] if result.summary else []
    detection = data.get("detection", {})
    lines.append("")
    lines.append(
        f"Format: {data.get('parser')} (confidence {detection.get('confidence', '?')})"
    )
    lines.append(
        f"Lines: {data.get('total_lines')} parsed, "
        f"{data.get('events_matched')} matched, "
        f"{data.get('warning_count')} warnings"
    )
    if data.get("time_first"):
        lines.append(f"Time range: {data['time_first']} .. {data['time_last']}")
    if data.get("filters"):
        lines.append(
            "Filters: " + ", ".join(f"{k}={v}" for k, v in data["filters"].items())
        )
    if data.get("warnings"):
        lines.append("")
        lines.append(f"Parse warnings (showing {len(data['warnings'])}):")
        for w in data["warnings"][:10]:
            lines.append(f"  line {w.get('line_number')}: {w.get('reason')}")
    lines.append("")
    lines.extend(
        _hist_lines(
            "Severity",
            [[k, v] for k, v in data.get("severity_histogram", {}).items()],
        )
    )
    if data.get("status_histogram"):
        lines.append("")
        lines.extend(
            _hist_lines(
                "HTTP status",
                [[k, v] for k, v in data.get("status_histogram", {}).items()],
            )
        )
    lines.append("")
    lines.extend(_hist_lines("Top IPs", data.get("top_ips", [])))
    lines.append("")
    lines.extend(_hist_lines("Top hosts", data.get("top_hosts", [])))
    if data.get("bursts"):
        lines.append("")
        lines.append("Bursts:")
        for b in data["bursts"]:
            key = f" [{b['key']}]" if b.get("key") else ""
            window = f"{b['window_start']} (+{b.get('window_end') or ''}){key}"
            lines.append(f"  {window}: {b['count']} events")
    if data.get("errors"):
        lines.append("")
        lines.append(f"Errors ({len(data['errors'])} shown):")
        for entry in data["errors"][:10]:
            event = entry["event"]
            lines.append(
                f"  line {event.get('line_number')} [{event.get('severity')}] "
                f"{(event.get('message') or '')[:100]}"
            )
            for ctx in entry.get("context_before", []):
                lines.append(f"    | {ctx[:100]}")
            for ctx in entry.get("context_after", []):
                lines.append(f"    | {ctx[:100]}")
    if data.get("hourly"):
        lines.append("")
        lines.extend(_hist_lines("Events per hour", data["hourly"][:12]))
        if len(data["hourly"]) > 12:
            lines.append(f"  ... and {len(data['hourly']) - 12} more buckets")
    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title} (confidence {f.confidence})")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)
