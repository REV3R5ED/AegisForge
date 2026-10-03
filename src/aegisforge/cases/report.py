"""Reproducible case report artifacts.

``generate_report`` assembles a self-contained bundle directory::

    <output>/
        case.json               # case metadata, notes, findings
        evidence-manifest.json  # every attached evidence record + hashes
        timeline.json           # unified timeline (timed + untimed)
        timeline.csv            # same, one row per entry
        findings.json           # tracked findings with indicators
        notes.txt               # analyst notes, chronological
        report-manifest.json    # SHA-256 of every artifact above

The report manifest lets anyone verify the bundle has not been
altered since generation. An existing non-empty output directory is
refused unless ``force`` is passed.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from aegisforge.cases.models import CaseMetadata
from aegisforge.cases.store import CaseError
from aegisforge.cases.timeline import build_case_timeline, timeline_to_dict
from aegisforge.core.logging import utc_now_iso
from aegisforge.forensics import hashing as hashing_mod

ARTIFACTS = (
    "case.json",
    "evidence-manifest.json",
    "timeline.json",
    "timeline.csv",
    "findings.json",
    "notes.txt",
)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _notes_text(case: CaseMetadata) -> str:
    lines = [f"Analyst notes for {case.case_id} — {case.title}", ""]
    for note in case.notes:
        lines.append(f"[{note.created}] {note.author}: {note.text}")
    return "\n".join(lines) + "\n"


def _timeline_csv(timed: list[Any], untimed: list[Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "source", "kind", "summary", "detail"])
    for entry in list(timed) + list(untimed):
        writer.writerow(
            [
                entry.timestamp or "",
                entry.source,
                entry.kind,
                entry.summary,
                entry.detail,
            ]
        )
    return buf.getvalue()


def generate_report(
    case: CaseMetadata, output: str, force: bool = False
) -> dict[str, Any]:
    """Build the report bundle; returns the report manifest dict."""
    out = Path(output)
    if out.exists() and any(out.iterdir()) and not force:
        raise CaseError(
            f"report output {output!r} already exists and is not empty "
            "(pass --force to overwrite)"
        )
    out.mkdir(parents=True, exist_ok=True)

    timed, untimed = build_case_timeline(case)
    timeline = timeline_to_dict(timed, untimed)

    payloads: dict[str, str] = {
        "case.json": json.dumps(case.to_dict(), indent=2) + "\n",
        "evidence-manifest.json": json.dumps(
            {
                "case_id": case.case_id,
                "generated": utc_now_iso(),
                "evidence": [e.to_dict() for e in case.evidence],
                "count": len(case.evidence),
                "note": "Stored files are copies; SHA-256 recorded at attach "
                "time. Sources were never modified.",
            },
            indent=2,
        )
        + "\n",
        "timeline.json": json.dumps(timeline, indent=2) + "\n",
        "timeline.csv": _timeline_csv(timed, untimed),
        "findings.json": json.dumps(
            {
                "case_id": case.case_id,
                "generated": utc_now_iso(),
                "findings": [f.to_dict() for f in case.findings],
                "count": len(case.findings),
            },
            indent=2,
        )
        + "\n",
        "notes.txt": _notes_text(case),
    }
    for name in ARTIFACTS:
        _write_text(out / name, payloads[name])

    manifest: dict[str, Any] = {
        "case_id": case.case_id,
        "generated": utc_now_iso(),
        "artifacts": {},
    }
    for name in ARTIFACTS:
        digest = hashing_mod.hash_file(str(out / name), algorithms=("sha256",))
        manifest["artifacts"][name] = digest["sha256"]
    _write_text(out / "report-manifest.json", json.dumps(manifest, indent=2) + "\n")

    return {
        "output": str(out),
        "artifacts": list(ARTIFACTS) + ["report-manifest.json"],
        "artifact_count": len(ARTIFACTS) + 1,
        "manifest": manifest,
        "evidence_count": len(case.evidence),
        "finding_count": len(case.findings),
        "timeline_entries": len(timed) + len(untimed),
    }
