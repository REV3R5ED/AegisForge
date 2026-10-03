"""Write report artifacts to disk: HTML, PDF, JSON, CSV + manifest.

``write_report`` produces, depending on *formats*::

    <output>/
        report.html             # self-contained HTML report
        report.pdf              # print-friendly text PDF
        report.json             # complete report data model
        findings.csv            # one row per finding
        timeline.csv            # one row per timeline entry
        evidence.csv            # one row per evidence item
        indicators.csv          # one row per indicator
        report-manifest.json    # SHA-256 of every artifact above

An existing non-empty output directory is refused unless ``force`` is
passed, mirroring ``case report``.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from aegisforge.cases.store import CaseError
from aegisforge.forensics import hashing as hashing_mod
from aegisforge.reporting.html import render_html
from aegisforge.reporting.pdf import render_pdf

FORMATS = ("html", "pdf", "json", "csv", "all")


def _csv_findings(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "finding_id",
            "title",
            "status",
            "severity",
            "confidence",
            "observed_label",
            "observed",
            "inferred_label",
            "inferred",
        ]
    )
    for f in data["findings"]:
        obs, inf = f["observed"], f["inferred"]
        observed_bits = list(obs.get("evidence", []))
        observed_bits += [
            f"{i['value']} ({i['type']})" for i in obs.get("indicators", [])
        ]
        inferred_text = inf.get("reason") or inf.get("detail") or ""
        w.writerow(
            [
                f["finding_id"],
                f["title"],
                f.get("status", ""),
                inf["severity"],
                inf["confidence"],
                obs["label"],
                " | ".join(observed_bits),
                inf["label"],
                inferred_text,
            ]
        )
    return buf.getvalue()


def _csv_timeline(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "source", "kind", "summary", "detail"])
    for e in data["timeline"]:
        w.writerow(
            [
                e.get("timestamp") or "",
                e.get("source", ""),
                e.get("kind", ""),
                e.get("summary", ""),
                e.get("detail", ""),
            ]
        )
    return buf.getvalue()


def _csv_evidence(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        ["evidence_id", "kind", "original_path", "sha256", "size", "attached_at"]
    )
    for e in data["evidence_inventory"]:
        w.writerow(
            [
                e["evidence_id"],
                e["kind"],
                e["original_path"],
                e["sha256"],
                e["size"],
                e["attached_at"],
            ]
        )
    return buf.getvalue()


def _csv_indicators(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["value", "type", "verdict", "verdict_source", "sources"])
    for i in data["indicators"]:
        w.writerow(
            [
                i["value"],
                i["type"],
                i["verdict"],
                i["verdict_source"],
                " | ".join(i["sources"]),
            ]
        )
    return buf.getvalue()


def csv_sections(data: dict[str, Any]) -> dict[str, str]:
    """One CSV string per section, keyed by file name."""
    return {
        "findings.csv": _csv_findings(data),
        "timeline.csv": _csv_timeline(data),
        "evidence.csv": _csv_evidence(data),
        "indicators.csv": _csv_indicators(data),
    }


def write_report(
    data: dict[str, Any],
    output: str,
    formats: tuple[str, ...] = ("all",),
    force: bool = False,
) -> dict[str, Any]:
    """Render *data* to *output* in the requested formats.

    Returns a summary dict for the CLI result envelope.
    """
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise CaseError(f"unknown report format(s): {', '.join(unknown)}")
    want_all = "all" in formats
    want = lambda name: want_all or name in formats  # noqa: E731

    out = Path(output)
    if out.exists() and any(out.iterdir()) and not force:
        raise CaseError(
            f"report output {output!r} already exists and is not empty "
            "(pass --force to overwrite)"
        )
    out.mkdir(parents=True, exist_ok=True)

    payloads: dict[str, bytes] = {}
    if want("html"):
        payloads["report.html"] = render_html(data).encode("utf-8")
    if want("pdf"):
        payloads["report.pdf"] = render_pdf(data)
    if want("json"):
        payloads["report.json"] = (
            json.dumps(data, indent=2, default=str) + "\n"
        ).encode("utf-8")
    if want("csv"):
        for name, text in csv_sections(data).items():
            payloads[name] = text.encode("utf-8")

    for name, content in payloads.items():
        (out / name).write_bytes(content)

    manifest: dict[str, Any] = {
        "report": data["title"],
        "tool": f"aegisforge {data['tool_version']}",
        "generated": data["generated"],
        "artifacts": {},
    }
    for name in payloads:
        digest = hashing_mod.hash_file(str(out / name), algorithms=("sha256",))
        manifest["artifacts"][name] = digest["sha256"]
    (out / "report-manifest.json").write_bytes(
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    )

    return {
        "output": str(out),
        "formats": sorted(formats),
        "artifacts": sorted(payloads) + ["report-manifest.json"],
        "artifact_count": len(payloads) + 1,
        "manifest": manifest["artifacts"],
        "title": data["title"],
    }
