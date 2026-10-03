"""Professional reporting command implementations."""

from __future__ import annotations

import argparse
import os
from typing import Any

from aegisforge.cases.store import CaseError
from aegisforge.core.config import AppConfig
from aegisforge.core.events import Event
from aegisforge.core.results import Result
from aegisforge.domain import investigate as investigate_mod
from aegisforge.forensics import hashing as forensics_hashing_mod
from aegisforge.forensics import inventory as forensics_inventory_mod
from aegisforge.forensics import timeline as forensics_timeline_mod
from aegisforge.intel import normalize as intel_normalize_mod
from aegisforge.intel.builtin import LocalBlocklistProvider
from aegisforge.logs import analyze as logs_analyze_mod
from aegisforge.logs.analyze import AnalyzeOptions
from aegisforge.logs.filters import LogFilter
from aegisforge.network.validation import ValidationError
from aegisforge.pcap import analyze as pcap_analyze_mod
from aegisforge.pcap.reader import PcapError
from aegisforge.reporting import exports as reporting_exports_mod
from aegisforge.reporting import model as reporting_model_mod

from .forensics import _check_root
from .pcap import _pcap_check, _pcap_options
from .shared import _case_or_fail


def _report_source_file(path: str) -> dict[str, Any]:
    """Describe a source file for a scan report (read-only, hashed)."""
    info: dict[str, Any] = {"path": path, "sha256": "", "size": 0}
    try:
        digest = forensics_hashing_mod.hash_file(path, algorithms=("sha256",))
        info["sha256"] = digest.get("sha256", "")
    except OSError:
        pass
    try:
        info["size"] = os.path.getsize(path)
    except OSError:
        pass
    return info


def _report_verdicts(
    case: Any, cfg: AppConfig
) -> dict[tuple[str, str], dict[str, str]]:
    """Offline indicator verdicts for a case report (never touches network).

    Only the local blocklist is consulted; when it is not configured
    every indicator is honestly reported as verdict ``unknown``.
    """
    verdicts: dict[tuple[str, str], dict[str, str]] = {}
    provider = LocalBlocklistProvider()
    blocklist_path = cfg.get("intel_blocklist")
    if blocklist_path:
        provider.configure({"path": str(blocklist_path)})
    configured = provider.is_configured()
    for finding in case.findings:
        for link in finding.indicators:
            norm = intel_normalize_mod.normalize_indicator(link.value)
            if norm.rejected:
                continue
            key = (norm.type, norm.value)
            if key in verdicts:
                continue
            if configured:
                record = provider.lookup(norm)
                verdicts[key] = {
                    "verdict": record.verdict,
                    "source": f"local-blocklist: {record.detail}",
                    "detail": record.detail,
                }
            else:
                verdicts[key] = {
                    "verdict": "unknown",
                    "source": "no intel provider configured for this report",
                    "detail": (
                        "local blocklist not configured; verdict unavailable offline"
                    ),
                }
    return verdicts


def _write_report_result(
    result: Result,
    data: dict[str, Any],
    args: argparse.Namespace,
    event_type: str,
    event_evidence: dict[str, Any],
) -> Result:
    try:
        summary = reporting_exports_mod.write_report(
            data, args.output, formats=(args.format,), force=args.force
        )
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = summary
    result.summary = (
        f"{data['title']} written to {summary['output']}: "
        f"{summary['artifact_count']} artifact(s) ({args.format})"
    )
    result.add_event(
        Event(
            event_type=event_type,
            source="aegisforge",
            evidence={
                **event_evidence,
                "output": summary["output"],
                "artifacts": summary["artifact_count"],
            },
        )
    )
    return result


def cmd_report_case(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="report case", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    verdicts = _report_verdicts(case, cfg)
    data = reporting_model_mod.build_case_report_data(case, verdicts=verdicts)
    return _write_report_result(
        result,
        data,
        args,
        "report.case.generated",
        {"case_id": case.case_id},
    )


def cmd_report_logs(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="report logs", target=args.file)
    if not os.path.isfile(args.file):
        result.fail(f"file does not exist: {args.file}")
        return result
    try:
        analysis = logs_analyze_mod.analyze_file(
            args.file,
            LogFilter(),
            AnalyzeOptions(parser_name=args.log_format or "auto"),
        )
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    timeline = [
        {
            "timestamp": event.get("timestamp"),
            "source": f"logs:{args.file}",
            "kind": "log-event",
            "summary": str(event.get("message") or event.get("raw") or ""),
            "detail": "",
        }
        for event in analysis.to_dict().get("events", [])[:500]
    ]
    data = reporting_model_mod.build_scan_report_data(
        kind="logs",
        source_label=args.file,
        source_files=[_report_source_file(args.file)],
        findings=analysis.findings,
        timeline=timeline,
        analysis_summary=(
            f"{analysis.events_matched} event(s) matched ({analysis.parser})."
        ),
    )
    return _write_report_result(
        result, data, args, "report.logs.generated", {"file": args.file}
    )


def cmd_report_pcap(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="report pcap", target=args.file)
    problem = _pcap_check(args.file)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        options = _pcap_options(args, cfg)
        summary = pcap_analyze_mod.summarize(args.file, options)
        tl = pcap_analyze_mod.timeline(args.file, options)
    except PcapError as exc:
        result.fail(str(exc))
        return result
    timeline = [
        {
            "timestamp": event.timestamp,
            "source": event.source,
            "kind": event.kind,
            "summary": event.summary,
            "detail": "",
        }
        for event in tl.events
    ]
    data = reporting_model_mod.build_scan_report_data(
        kind="pcap",
        source_label=args.file,
        source_files=[_report_source_file(args.file)],
        findings=summary.findings,
        timeline=timeline,
        analysis_summary=(
            f"{summary.packet_count} packet(s), {summary.total_bytes} bytes."
        ),
    )
    return _write_report_result(
        result, data, args, "report.pcap.generated", {"file": args.file}
    )


def cmd_report_forensics(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="report forensics", target=args.path)
    problem = _check_root(args.path)
    if problem is not None:
        result.fail(problem)
        return result
    try:
        inv = forensics_inventory_mod.run_inventory(
            args.path, hash_algorithms=("sha256",)
        )
        entries = forensics_timeline_mod.build_timeline(inv.files)
    except (ValidationError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    timeline = [
        {
            "timestamp": entry.timestamp,
            "source": f"files:{args.path}",
            "kind": f"file-{entry.kind}",
            "summary": entry.path,
            "detail": "",
        }
        for entry in entries
    ]
    data = reporting_model_mod.build_scan_report_data(
        kind="forensics",
        source_label=args.path,
        source_files=[_report_source_file(args.path)],
        findings=[],
        timeline=timeline,
        analysis_summary=(
            f"{inv.stats.files} file(s), {inv.stats.total_bytes} byte(s) "
            "inventoried read-only."
        ),
    )
    return _write_report_result(
        result, data, args, "report.forensics.generated", {"path": args.path}
    )


def cmd_report_domain(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="report domain", target=args.target)
    timeout = args.timeout if args.timeout is not None else cfg["domain_dns_timeout"]
    try:
        options = investigate_mod.DomainOptions(
            resolver=args.resolver or cfg.get("domain_resolver") or None,
            timeout=timeout,
            rdap=not args.no_rdap,
            whois=not args.no_whois,
            web=not args.no_web,
            tls=not args.no_tls,
        )
        report = investigate_mod.investigate_domain(args.target, options)
    except ValidationError as exc:
        result.fail(str(exc))
        return result
    findings = investigate_mod.analyze_findings(report)
    data = reporting_model_mod.build_scan_report_data(
        kind="domain",
        source_label=args.target,
        source_files=[],
        findings=findings,
        timeline=[],
        analysis_summary=(
            f"domain investigation of {report.domain}: {len(findings)} "
            f"finding(s), {len(report.errors)} error(s)."
        ),
        analysis_data=report.to_dict(),
    )
    return _write_report_result(
        result, data, args, "report.domain.generated", {"target": args.target}
    )


def render_report(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  output:    {data.get('output')}")
    lines.append(f"  artifacts: {data.get('artifact_count')}")
    manifest = data.get("manifest") or {}
    if manifest:
        lines.append("")
        lines.append("  report manifest (SHA-256 per artifact):")
        for name in data.get("artifacts", []):
            digest = manifest.get(name, "")
            lines.append(f"    {name}: {digest[:16]}…" if digest else f"    {name}")
    return "\n".join(lines)
