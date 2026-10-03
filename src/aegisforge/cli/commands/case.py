"""Incident case management command implementations."""

from __future__ import annotations

import argparse

from aegisforge.cases import evidence as cases_evidence_mod
from aegisforge.cases import findings as cases_findings_mod
from aegisforge.cases import report as cases_report_mod
from aegisforge.cases import store as cases_store_mod
from aegisforge.cases import timeline as cases_timeline_mod
from aegisforge.cases.store import CaseError
from aegisforge.core.config import AppConfig
from aegisforge.core.findings import Finding
from aegisforge.core.results import Result

from .shared import _case_event, _case_or_fail


def cmd_case_create(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case create")
    try:
        case = cases_store_mod.create_case(args.title, note=args.note)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.target = case.case_id
    result.data = case.to_dict()
    result.summary = f"case {case.case_id} created: {case.title}"
    result.add_event(_case_event("case.created", case.case_id, {"title": case.title}))
    return result


def cmd_case_list(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case list")
    cases = cases_store_mod.list_cases()
    result.data = {
        "cases": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status,
                "created": c.created,
                "evidence": len(c.evidence),
                "findings": len(c.findings),
                "notes": len(c.notes),
            }
            for c in cases
        ],
        "count": len(cases),
    }
    result.summary = f"{len(cases)} case(s)"
    return result


def cmd_case_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case show", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    result.data = case.to_dict()
    result.summary = (
        f"{case.case_id}: {case.title} [{case.status}] — "
        f"{len(case.evidence)} evidence, {len(case.findings)} findings, "
        f"{len(case.notes)} notes"
    )
    return result


def cmd_case_attach(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case attach", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        record = cases_evidence_mod.attach_evidence(case, args.kind, args.source)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = record.to_dict()
    result.summary = (
        f"attached {args.source} to {case.case_id} as "
        f"{record.evidence_id} (sha256 {record.sha256[:16]}…)"
    )
    result.add_event(
        _case_event(
            "case.evidence.attached",
            case.case_id,
            {
                "evidence_id": record.evidence_id,
                "kind": record.kind,
                "sha256": record.sha256,
            },
        )
    )
    return result


def cmd_case_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case timeline", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    timed, untimed = cases_timeline_mod.build_case_timeline(case)
    if args.limit is not None and args.limit >= 0:
        timed = timed[: args.limit]
    result.data = {
        "case_id": case.case_id,
        "timeline_entries": [e.to_dict() for e in timed],
        "untimed": [e.to_dict() for e in untimed],
        "timed_count": len(timed),
        "untimed_count": len(untimed),
        "note": "Filesystem timestamps are filesystem metadata claims, not "
        "content claims. Untimed events are listed separately, never dropped.",
    }
    result.summary = (
        f"{case.case_id}: {len(timed)} timed event(s), {len(untimed)} untimed event(s)"
    )
    result.add_event(
        _case_event(
            "case.timeline.built",
            case.case_id,
            {"timed": len(timed), "untimed": len(untimed)},
        )
    )
    return result


def cmd_case_finding(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case finding", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        finding = cases_findings_mod.add_case_finding(
            case,
            title=args.title,
            severity=args.severity,
            confidence=args.confidence,
            detail=args.detail or "",
        )
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = finding.to_dict()
    result.summary = (
        f"finding {finding.finding_id} recorded in {case.case_id}: "
        f"{finding.title} [{finding.severity}]"
    )
    result.add_finding(
        Finding(
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            reason=finding.detail,
            evidence=[f"case {case.case_id}", f"finding {finding.finding_id}"],
        )
    )
    result.add_event(
        _case_event(
            "case.finding.recorded",
            case.case_id,
            {"finding_id": finding.finding_id, "severity": finding.severity},
        )
    )
    return result


def cmd_case_findings(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case findings", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    findings = case.findings
    if args.status:
        findings = [f for f in findings if f.status == args.status]
    result.data = {
        "case_id": case.case_id,
        "case_findings": [f.to_dict() for f in findings],
        "count": len(findings),
    }
    result.summary = f"{case.case_id}: {len(findings)} finding(s)"
    return result


def cmd_case_link(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case link", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        link = cases_findings_mod.link_indicator(
            case, args.finding, args.indicator, type_override=args.type
        )
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = link.to_dict()
    origin = "analyst-specified" if link.type_source == "specified" else "guessed"
    result.summary = (
        f"linked {link.value!r} ({link.type}, type {origin}) "
        f"to {args.finding} in {case.case_id}"
    )
    result.add_event(
        _case_event(
            "case.indicator.linked",
            case.case_id,
            {
                "finding_id": args.finding,
                "indicator": link.value,
                "type": link.type,
                "type_source": link.type_source,
            },
        )
    )
    return result


def cmd_case_note(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case note", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        note = cases_findings_mod.add_note(case, args.text)
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = note.to_dict()
    result.summary = f"note added to {case.case_id}"
    result.add_event(_case_event("case.note.added", case.case_id, {}))
    return result


def cmd_case_report(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case report", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    try:
        summary = cases_report_mod.generate_report(case, args.output, force=args.force)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = summary
    result.summary = (
        f"report for {case.case_id} written to {summary['output']}: "
        f"{summary['artifact_count']} artifact(s)"
    )
    result.add_event(
        _case_event(
            "case.report.generated",
            case.case_id,
            {"output": summary["output"], "artifacts": summary["artifact_count"]},
        )
    )
    return result


def cmd_case_status(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="case status", target=args.case_id)
    case = _case_or_fail(result, args.case_id)
    if case is None:
        return result
    if args.status is None:
        result.data = {"case_id": case.case_id, "status": case.status}
        result.summary = f"{case.case_id} status: {case.status}"
        return result
    try:
        cases_findings_mod.set_case_status(case, args.status, note=args.note)
        cases_store_mod.save_case(case)
    except CaseError as exc:
        result.fail(str(exc))
        return result
    result.data = {"case_id": case.case_id, "status": case.status}
    result.summary = f"{case.case_id} status -> {case.status}"
    result.add_event(
        _case_event("case.status.changed", case.case_id, {"status": case.status})
    )
    return result


def render_case_create(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  case id:  {data.get('case_id')}")
    lines.append(f"  title:    {data.get('title')}")
    lines.append(f"  status:   {data.get('status')}")
    lines.append(f"  created:  {data.get('created')}")
    return "\n".join(lines)


def render_case_list(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    cases = data.get("cases", [])
    if cases:
        lines.append("")
        lines.append(f"{'CASE ID':<16}{'STATUS':<12}{'EVID':>5}{'FIND':>5}  TITLE")
        for c in cases:
            lines.append(
                f"{c['case_id']:<16}{c['status']:<12}{c['evidence']:>5}"
                f"{c['findings']:>5}  {c['title']}"
            )
    return "\n".join(lines)


def render_case_show(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  title:    {data.get('title')}")
    lines.append(f"  status:   {data.get('status')}")
    lines.append(f"  created:  {data.get('created')}")
    evidence = data.get("evidence", [])
    if evidence:
        lines.append("")
        lines.append("Evidence:")
        for e in evidence:
            lines.append(
                f"  {e['evidence_id']} [{e['kind']}] {e['stored_path']} "
                f"(sha256 {e['sha256'][:12]}…)"
            )
    findings = data.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Findings:")
        for f in findings:
            lines.append(
                f"  {f['finding_id']} [{f['severity']}/{f['status']}] {f['title']}"
            )
    notes = data.get("notes", [])
    if notes:
        lines.append("")
        lines.append(f"Notes: {len(notes)} (see --json for full text)")
    return "\n".join(lines)


def render_case_attach(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  evidence id:  {data.get('evidence_id')}")
    lines.append(f"  kind:         {data.get('kind')}")
    lines.append(f"  stored as:    {data.get('stored_path')}")
    lines.append(f"  sha256:       {data.get('sha256')}")
    lines.append(f"  attached at:  {data.get('attached_at')} (UTC)")
    return "\n".join(lines)


def render_case_timeline(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    entries = data.get("timeline_entries", [])
    if entries:
        lines.append("")
        lines.append(f"{'TIMESTAMP (UTC)':<30}{'SOURCE':<22}{'KIND':<16}SUMMARY")
        for e in entries[:80]:
            lines.append(
                f"{(e.get('timestamp') or ''):<30}{e.get('source', ''):<22}"
                f"{e.get('kind', ''):<16}{e.get('summary', '')[:60]}"
            )
        if len(entries) > 80:
            lines.append(f"... and {len(entries) - 80} more (see --json)")
    untimed = data.get("untimed", [])
    if untimed:
        lines.append("")
        lines.append(
            f"Untimed ({len(untimed)} — no parseable timestamp, listed "
            "separately, never dropped):"
        )
        for e in untimed[:20]:
            lines.append(f"  [{e.get('source')}] {e.get('summary', '')[:70]}")
        if len(untimed) > 20:
            lines.append(f"  ... and {len(untimed) - 20} more (see --json)")
    lines.append("")
    lines.append(data.get("note", ""))
    return "\n".join(lines)


def render_case_finding(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  severity:   {data.get('severity')}")
    lines.append(f"  confidence: {data.get('confidence')}")
    lines.append(f"  status:     {data.get('status')}")
    if data.get("detail"):
        lines.append(f"  detail:     {data.get('detail')}")
    return "\n".join(lines)


def render_case_findings(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    findings = data.get("case_findings", [])
    if findings:
        lines.append("")
        lines.append(f"{'FINDING ID':<22}{'SEVERITY':<10}{'STATUS':<14}TITLE")
        for f in findings:
            indicators = ", ".join(
                f"{i['value']} ({i['type']})" for i in f.get("indicators", [])
            )
            lines.append(
                f"{f['finding_id']:<22}{f['severity']:<10}{f['status']:<14}{f['title']}"
            )
            if indicators:
                lines.append(f"  indicators: {indicators}")
    return "\n".join(lines)


def render_case_link(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    origin = (
        "analyst-specified"
        if data.get("type_source") == "specified"
        else "guessed from value shape (not a verified classification)"
    )
    lines.append(f"  value: {data.get('value')}")
    lines.append(f"  type:  {data.get('type')} ({origin})")
    return "\n".join(lines)


def render_case_note(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  [{data.get('created')}] {data.get('author')}: {data.get('text')}")
    return "\n".join(lines)


def render_case_report(result: Result) -> str:
    data = result.data
    lines = [result.summary] if result.summary else []
    lines.append("")
    lines.append(f"  output:   {data.get('output')}")
    lines.append(f"  evidence: {data.get('evidence_count')} file(s)")
    lines.append(f"  findings: {data.get('finding_count')}")
    lines.append(f"  timeline: {data.get('timeline_entries')} entr(ies)")
    manifest = (data.get("manifest") or {}).get("artifacts", {})
    if manifest:
        lines.append("")
        lines.append("  report manifest (SHA-256 per artifact):")
        for name, digest in manifest.items():
            lines.append(f"    {name}: {digest[:16]}…")
    return "\n".join(lines)


def render_case_status(result: Result) -> str:
    lines = [result.summary] if result.summary else []
    return "\n".join(lines)
