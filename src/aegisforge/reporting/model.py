"""Report data model: one dict describing a complete report.

Both case reports and single-analysis ("scan") reports are built here,
so HTML, PDF, JSON and CSV renderers all work from the same structure.
Every finding carries explicit ``observed`` / ``inferred`` blocks; the
executive summary is auto-generated and labelled as such.
"""

from __future__ import annotations

from typing import Any

from aegisforge import __version__ as TOOL_VERSION
from aegisforge.cases.models import CaseFinding
from aegisforge.cases.timeline import build_case_timeline
from aegisforge.core.findings import SEVERITIES, Finding
from aegisforge.core.logging import utc_now_iso
from aegisforge.core.plugins import get_registry
from aegisforge.reporting.methodology import NOT_CLAIMS, methodology_sections


def split_scan_finding(finding: Finding) -> dict[str, Any]:
    """Observed-vs-inferred split for an analysis :class:`Finding`.

    ``evidence`` is what the tool directly saw; ``reason`` is the
    conclusion it drew. Severity and confidence are always judgments.
    """
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "observed": {
            "label": "OBSERVED",
            "evidence": list(finding.evidence),
            "related_events": list(finding.related_events),
            "note": "Directly recorded by the analysis; quoted verbatim.",
        },
        "inferred": {
            "label": "INFERRED",
            "reason": finding.reason,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "note": (
                "The tool's conclusion from the observations above. "
                "Severity and confidence are judgments, not measurements."
            ),
        },
        "timestamp": finding.timestamp,
        "extra": dict(finding.data),
    }


def split_case_finding(finding: CaseFinding) -> dict[str, Any]:
    """Observed-vs-inferred split for a tracked case finding.

    A case finding is analyst-authored, so the split is honest about
    that: the recorded title, linked indicator values and lifecycle
    facts are observed; the detail text, severity and confidence are
    the analyst's inference.
    """
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "status": finding.status,
        "observed": {
            "label": "OBSERVED",
            "title_recorded": finding.title,
            "indicators": [
                {
                    "value": link.value,
                    "type": link.type,
                    "type_source": link.type_source,
                }
                for link in finding.indicators
            ],
            "recorded_at": finding.created,
            "note": "Recorded in the case as written; indicator values are "
            "verbatim strings from the evidence.",
        },
        "inferred": {
            "label": "INFERRED",
            "detail": finding.detail,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "note": (
                "The analyst's conclusion. Severity and confidence are "
                "judgments, not measurements."
            ),
        },
    }


def _top_findings(split: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    order = {sev: idx for idx, sev in enumerate(reversed(SEVERITIES))}
    ranked = sorted(
        split,
        key=lambda f: (
            order.get(f["inferred"]["severity"], 0),
            -f["inferred"]["confidence"],
        ),
    )
    return [
        {
            "finding_id": f["finding_id"],
            "title": f["title"],
            "severity": f["inferred"]["severity"],
            "confidence": f["inferred"]["confidence"],
        }
        for f in ranked[:limit]
    ]


def _severity_counts(split: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for f in split:
        sev = f["inferred"]["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _date_range(timeline: list[dict[str, Any]]) -> dict[str, str | None]:
    stamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    if not stamps:
        return {"start": None, "end": None}
    return {"start": min(stamps), "end": max(stamps)}


def executive_summary(
    *,
    subject: str,
    counts: dict[str, int],
    split_findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    extra_line: str = "",
) -> dict[str, Any]:
    """Auto-generated executive summary, labelled as generated."""
    sev_counts = _severity_counts(split_findings)
    sev_phrase = (
        ", ".join(f"{n} {sev}" for sev, n in sev_counts.items() if n) or "no findings"
    )
    top = _top_findings(split_findings, limit=3)
    dr = _date_range(timeline)
    if dr["start"] and dr["end"]:
        range_phrase = f"spanning {dr['start']} to {dr['end']}"
    else:
        range_phrase = "with no timestamped entries"
    paragraph = (
        f"{subject} It contains {counts.get('evidence', 0)} evidence item(s), "
        f"{counts.get('findings', 0)} finding(s) ({sev_phrase}), "
        f"{counts.get('timeline_entries', 0)} timeline entr(ies) {range_phrase}, "
        f"and {counts.get('indicators', 0)} unique indicator(s)."
    )
    if top:
        first = top[0]
        paragraph += (
            f" Top finding: {first['title']!r} "
            f"({first['severity']}, confidence {first['confidence']})."
        )
    if extra_line:
        paragraph += " " + extra_line
    paragraph += (
        " This summary was generated automatically by AegisForge and must "
        "be reviewed by an analyst before distribution."
    )
    return {
        "generated": True,
        "generated_by": f"aegisforge {TOOL_VERSION}",
        "analyst_review_required": True,
        "paragraph": paragraph,
        "counts": counts,
        "findings_by_severity": sev_counts,
        "top_findings": top,
        "date_range": dr,
        "does_not_claim": list(NOT_CLAIMS),
    }


def build_case_report_data(
    case: Any,
    *,
    verdicts: dict[tuple[str, str], dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Assemble the complete report data model for a case."""
    timed, untimed = build_case_timeline(case)
    timeline = [
        {
            "timestamp": e.timestamp,
            "source": e.source,
            "kind": e.kind,
            "summary": e.summary,
            "detail": e.detail,
        }
        for e in list(timed) + list(untimed)
    ]

    split_findings = [split_case_finding(f) for f in case.findings]

    # Deduped indicators from finding links, with verdicts.
    verdicts = verdicts or {}
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in case.findings:
        for link in finding.indicators:
            key = (link.type, link.value)
            entry = seen.setdefault(
                key,
                {
                    "value": link.value,
                    "type": link.type,
                    "type_source": link.type_source,
                    "sources": [],
                },
            )
            if finding.finding_id not in entry["sources"]:
                entry["sources"].append(finding.finding_id)
    indicators = []
    for (itype, value), entry in sorted(seen.items()):
        verdict = verdicts.get((itype, value), {})
        indicators.append(
            {
                **entry,
                "verdict": verdict.get("verdict", "unknown"),
                "verdict_source": verdict.get(
                    "source", "no intel provider consulted for this report"
                ),
                "verdict_detail": verdict.get("detail", ""),
            }
        )

    evidence_inventory = [
        {
            "evidence_id": e.evidence_id,
            "kind": e.kind,
            "original_path": e.original_path,
            "stored_path": e.stored_path,
            "sha256": e.sha256,
            "size": e.size,
            "attached_at": e.attached_at,
        }
        for e in case.evidence
    ]

    counts = {
        "evidence": len(case.evidence),
        "findings": len(case.findings),
        "timeline_entries": len(timeline),
        "indicators": len(indicators),
        "notes": len(case.notes),
    }
    summary = executive_summary(
        subject=f"Case {case.case_id} ({case.title!r}) is {case.status}.",
        counts=counts,
        split_findings=split_findings,
        timeline=timeline,
    )

    return {
        "tool": "aegisforge",
        "tool_version": TOOL_VERSION,
        "report_kind": "case",
        "generated": utc_now_iso(),
        "title": f"Case report: {case.case_id}",
        "case": {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status,
            "created": case.created,
        },
        "executive_summary": summary,
        "evidence_inventory": evidence_inventory,
        "methodology": methodology_sections(get_registry()),
        "findings": split_findings,
        "timeline": timeline,
        "indicators": indicators,
        "analyst_notes": [
            {"created": n.created, "author": n.author, "text": n.text}
            for n in case.notes
        ],
        "supporting_evidence": [
            {
                "label": f"evidence {e['evidence_id']}",
                "path": e["stored_path"],
                "sha256": e["sha256"],
                "note": f"copy of {e['original_path']}; source never modified",
            }
            for e in evidence_inventory
        ],
    }


def build_scan_report_data(
    *,
    kind: str,
    source_label: str,
    source_files: list[dict[str, Any]],
    findings: list[Finding],
    timeline: list[dict[str, Any]] | None = None,
    analysis_summary: str = "",
    analysis_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the report data model for a single analysis.

    Reuses the same sections as case reports where applicable;
    sections that do not apply carry an explicit note instead of
    being silently omitted.
    """
    timeline = timeline or []
    split_findings = [split_scan_finding(f) for f in findings]
    counts = {
        "evidence": len(source_files),
        "findings": len(findings),
        "timeline_entries": len(timeline),
        "indicators": 0,
        "notes": 0,
    }
    summary = executive_summary(
        subject=f"{kind} analysis of {source_label}.",
        counts=counts,
        split_findings=split_findings,
        timeline=timeline,
        extra_line=analysis_summary,
    )
    return {
        "tool": "aegisforge",
        "tool_version": TOOL_VERSION,
        "report_kind": "scan",
        "scan_kind": kind,
        "generated": utc_now_iso(),
        "title": f"{kind} report: {source_label}",
        "source": {
            "label": source_label,
            "files": source_files,
        },
        "executive_summary": summary,
        "evidence_inventory": [
            {
                "evidence_id": f"SRC-{i + 1:02d}",
                "kind": kind,
                "original_path": f["path"],
                "stored_path": f["path"],
                "sha256": f.get("sha256", ""),
                "size": f.get("size", 0),
                "attached_at": utc_now_iso(),
                "note": "Source file read read-only; never modified.",
            }
            for i, f in enumerate(source_files)
        ],
        "methodology": methodology_sections(get_registry()),
        "findings": split_findings,
        "timeline": timeline,
        "indicators": [],
        "indicators_note": (
            "Indicator extraction is a case-level step (see 'intel "
            "correlate'); single-analysis reports do not enrich indicators."
        ),
        "analyst_notes": [],
        "supporting_evidence": [
            {
                "label": f"source file {i + 1}",
                "path": f["path"],
                "sha256": f.get("sha256", ""),
                "note": "SHA-256 computed at report time.",
            }
            for i, f in enumerate(source_files)
        ],
        "analysis": analysis_data or {},
    }
