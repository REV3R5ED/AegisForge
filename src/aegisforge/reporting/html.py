"""Self-contained HTML report renderer (inline CSS, no external assets).

The output is one ``.html`` file that renders from ``file://`` with no
network access: all styling is inline and there are no external
images, fonts or scripts.
"""

from __future__ import annotations

import html as html_mod
from typing import Any

_CSS = """
body{font-family:system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;
margin:0;color:#1a1a1a;background:#fff;line-height:1.5}
header{background:#0f2a44;color:#fff;padding:28px 36px}
header h1{margin:0 0 6px;font-size:26px}
header p{margin:2px 0;color:#bcd;font-size:13px}
nav{background:#f2f5f9;border-bottom:1px solid #d7dee7;padding:10px 36px;
font-size:13px}
nav a{color:#0f2a44;margin-right:16px;text-decoration:none}
nav a:hover{text-decoration:underline}
main{max-width:1020px;margin:0 auto;padding:24px 36px 60px}
h2{border-bottom:2px solid #0f2a44;padding-bottom:6px;margin-top:40px}
h3{margin-top:24px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13.5px}
th,td{border:1px solid #ccd4de;padding:7px 10px;text-align:left;
vertical-align:top}
th{background:#eef2f7}
tr:nth-child(even) td{background:#fafbfc}
code{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
font-size:12.5px;background:#f2f5f9;padding:1px 5px;border-radius:3px}
pre{background:#f2f5f9;border:1px solid #d7dee7;border-radius:4px;
padding:12px;overflow-x:auto;font-size:12.5px}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;
font-weight:600;color:#fff}
.sev-critical{background:#b00020}.sev-high{background:#d64500}
.sev-medium{background:#b8860b}.sev-low{background:#2e7d32}
.sev-info{background:#546e7a}
.obs,.inf{border-left:4px solid;padding:10px 14px;margin:10px 0;border-radius:4px}
.obs{border-color:#2e7d32;background:#f1f8f1}
.inf{border-color:#d64500;background:#fdf6ef}
.obs h4,.inf h4{margin:0 0 6px;font-size:13px;letter-spacing:1px}
.obs h4{color:#2e7d32}.inf h4{color:#d64500}
.notclaims{border:2px solid #b00020;border-radius:6px;padding:14px 18px;
background:#fff5f5;margin:16px 0}
.notclaims h3{margin-top:0;color:#b00020}
.generated{background:#fffbe6;border:1px solid #e0c341;border-radius:6px;
padding:12px 16px;margin:16px 0;font-size:13.5px}
footer{border-top:1px solid #d7dee7;color:#666;font-size:12px;
padding:18px 36px}
.mono{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
font-size:12.5px;word-break:break-all}
"""


def _e(text: Any) -> str:
    return html_mod.escape("" if text is None else str(text))


def _severity_badge(severity: str) -> str:
    sev = _e(severity)
    return f'<span class="badge sev-{sev}">{sev.upper()}</span>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    parts = ["<table><thead><tr>"]
    parts.extend(f"<th>{_e(h)}</th>" for h in headers)
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        parts.extend(f"<td>{cell}</td>" for cell in row)
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _finding_block(f: dict[str, Any]) -> str:
    obs = f["observed"]
    inf = f["inferred"]
    fid = _e(f["finding_id"])
    parts = [f'<section id="finding-{fid}">']
    parts.append(
        f"<h3>{_e(f['title'])} {_severity_badge(inf['severity'])} "
        f"<small>confidence {inf['confidence']}/100</small></h3>"
    )
    parts.append(
        f"<p><code>{fid}</code>"
        + (f" &middot; status: <code>{_e(f['status'])}</code>" if "status" in f else "")
        + "</p>"
    )
    parts.append('<div class="obs"><h4>OBSERVED</h4>')
    if obs.get("evidence"):
        parts.append("<ul>")
        parts.extend(f"<li><code>{_e(e)}</code></li>" for e in obs["evidence"])
        parts.append("</ul>")
    if obs.get("indicators"):
        parts.append("<p>Linked indicators:</p><ul>")
        for ind in obs["indicators"]:
            parts.append(
                f"<li><code>{_e(ind['value'])}</code> "
                f"({_e(ind['type'])}, type {_e(ind['type_source'])})</li>"
            )
        parts.append("</ul>")
    if obs.get("related_events"):
        parts.append("<p>Related events:</p><ul>")
        parts.extend(f"<li><code>{_e(e)}</code></li>" for e in obs["related_events"])
        parts.append("</ul>")
    parts.append(f"<p><small>{_e(obs.get('note', ''))}</small></p></div>")
    parts.append('<div class="inf"><h4>INFERRED</h4>')
    if inf.get("reason"):
        parts.append(f"<p>{_e(inf['reason'])}</p>")
    if inf.get("detail"):
        parts.append(f"<p>{_e(inf['detail'])}</p>")
    parts.append(f"<p><small>{_e(inf.get('note', ''))}</small></p></div>")
    if f.get("timestamp"):
        parts.append(f"<p><small>Recorded: {_e(f['timestamp'])}</small></p>")
    parts.append("</section>")
    return "".join(parts)


def render_html(data: dict[str, Any]) -> str:
    """Render the report data model as a self-contained HTML document."""
    summary = data["executive_summary"]
    counts = summary["counts"]
    sections: list[str] = []

    # Executive summary -------------------------------------------------
    sec = ['<section id="executive-summary"><h2>Executive summary</h2>']
    sec.append(
        '<div class="generated"><strong>Auto-generated summary.</strong> '
        "This text was produced by AegisForge from the case data below; "
        "an analyst must review it before distribution.</div>"
    )
    sec.append(f"<p>{_e(summary['paragraph'])}</p>")
    sec.append(
        _table(
            ["Metric", "Value"],
            [
                ["Evidence items", str(counts.get("evidence", 0))],
                ["Findings", str(counts.get("findings", 0))],
                ["Timeline entries", str(counts.get("timeline_entries", 0))],
                ["Unique indicators", str(counts.get("indicators", 0))],
                [
                    "Date range",
                    f"{summary['date_range']['start'] or '—'} → "
                    f"{summary['date_range']['end'] or '—'}",
                ],
            ],
        )
    )
    if summary["top_findings"]:
        sec.append("<h3>Top findings</h3>")
        sec.append(
            _table(
                ["Finding", "Severity", "Confidence"],
                [
                    [
                        _e(t["title"]),
                        _severity_badge(t["severity"]),
                        f"{t['confidence']}/100",
                    ]
                    for t in summary["top_findings"]
                ],
            )
        )
    sec.append('<div class="notclaims"><h3>What this report does not claim</h3><ul>')
    sec.extend(f"<li>{_e(c)}</li>" for c in summary["does_not_claim"])
    sec.append("</ul></div></section>")
    sections.append("".join(sec))

    # Evidence inventory ------------------------------------------------
    sec = ['<section id="evidence"><h2>Evidence inventory</h2>']
    if data["evidence_inventory"]:
        sec.append(
            _table(
                ["ID", "Kind", "Original path", "SHA-256", "Size", "Attached"],
                [
                    [
                        f"<code>{_e(e['evidence_id'])}</code>",
                        _e(e["kind"]),
                        f"<code>{_e(e['original_path'])}</code>",
                        f"<span class='mono'>{_e(e['sha256'][:32])}…</span>",
                        str(e["size"]),
                        _e(e["attached_at"]),
                    ]
                    for e in data["evidence_inventory"]
                ],
            )
        )
    else:
        sec.append("<p>No evidence items.</p>")
    sec.append("</section>")
    sections.append("".join(sec))

    # Methodology --------------------------------------------------------
    sec = ['<section id="methodology"><h2>Methodology</h2>']
    sec.append(
        "<p>What each AegisForge module does, how it works, and what it "
        "cannot do — so findings can be judged without trusting the tool "
        "blindly.</p>"
    )
    for m in data["methodology"]:
        sec.append(
            f"<h3>{_e(m['module'])} <small>v{_e(m['version'])}</small></h3>"
            f"<p><strong>Purpose.</strong> {_e(m['purpose'])}</p>"
            f"<p><strong>Method.</strong> {_e(m['method'])}</p>"
            f"<p><strong>Limitations.</strong> {_e(m['limitations'])}</p>"
        )
    sec.append("</section>")
    sections.append("".join(sec))

    # Findings ------------------------------------------------------------
    sec = ['<section id="findings"><h2>Findings</h2>']
    sec.append(
        "<p>Every finding keeps <strong>observed</strong> facts separate "
        "from <strong>inferred</strong> conclusions.</p>"
    )
    for f in data["findings"]:
        sec.append(_finding_block(f))
    if not data["findings"]:
        sec.append("<p>No findings recorded.</p>")
    sec.append("</section>")
    sections.append("".join(sec))

    # Timeline -------------------------------------------------------------
    sec = ['<section id="timeline"><h2>Timeline</h2>']
    if data["timeline"]:
        sec.append(
            _table(
                ["Timestamp (UTC)", "Source", "Kind", "Summary"],
                [
                    [
                        _e(e["timestamp"] or "(untimed)"),
                        f"<code>{_e(e['source'])}</code>",
                        _e(e["kind"]),
                        _e(e["summary"]),
                    ]
                    for e in data["timeline"]
                ],
            )
        )
    else:
        sec.append("<p>No timeline entries.</p>")
    sec.append("</section>")
    sections.append("".join(sec))

    # Indicators ------------------------------------------------------------
    sec = ['<section id="indicators"><h2>Indicators</h2>']
    if data.get("indicators_note"):
        sec.append(f"<p><em>{_e(data['indicators_note'])}</em></p>")
    if data["indicators"]:
        sec.append(
            _table(
                ["Indicator", "Type", "Verdict", "Verdict source", "Seen in"],
                [
                    [
                        f"<code>{_e(i['value'])}</code>",
                        _e(i["type"]),
                        _e(i["verdict"]),
                        _e(i["verdict_source"]),
                        ", ".join(f"<code>{_e(s)}</code>" for s in i["sources"]),
                    ]
                    for i in data["indicators"]
                ],
            )
        )
    else:
        sec.append("<p>No indicators.</p>")
    sec.append("</section>")
    sections.append("".join(sec))

    # Analyst notes ----------------------------------------------------------
    if data.get("analyst_notes"):
        sec = ['<section id="notes"><h2>Analyst notes</h2><ul>']
        for n in data["analyst_notes"]:
            sec.append(
                f"<li><code>{_e(n['created'])}</code> "
                f"<strong>{_e(n['author'])}</strong>: {_e(n['text'])}</li>"
            )
        sec.append("</ul></section>")
        sections.append("".join(sec))

    # Supporting evidence / hashes -------------------------------------------
    sec = ['<section id="supporting-evidence"><h2>Supporting evidence and hashes</h2>']
    if data["supporting_evidence"]:
        sec.append(
            _table(
                ["Label", "Path", "SHA-256", "Note"],
                [
                    [
                        _e(s["label"]),
                        f"<code>{_e(s['path'])}</code>",
                        f"<span class='mono'>{_e(s['sha256'])}</span>",
                        _e(s["note"]),
                    ]
                    for s in data["supporting_evidence"]
                ],
            )
        )
    else:
        sec.append("<p>None.</p>")
    sec.append("</section>")
    sections.append("".join(sec))

    nav = "".join(
        f'<a href="#{anchor}">{label}</a>'
        for anchor, label in [
            ("executive-summary", "Summary"),
            ("evidence", "Evidence"),
            ("methodology", "Methodology"),
            ("findings", "Findings"),
            ("timeline", "Timeline"),
            ("indicators", "Indicators"),
            ("supporting-evidence", "Hashes"),
        ]
    )

    case_line = ""
    if data.get("case"):
        case_line = (
            f"Case {data['case']['case_id']} — {data['case']['title']} "
            f"({data['case']['status']})"
        )
    elif data.get("source"):
        case_line = f"{data.get('scan_kind', 'scan')}: {data['source']['label']}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(data["title"])}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
<h1>{_e(data["title"])}</h1>
<p>{_e(case_line)}</p>
<p>Generated {_e(data["generated"])} by AegisForge {_e(data["tool_version"])} (UTC)</p>
</header>
<nav>{nav}</nav>
<main>
{"".join(sections)}
</main>
<footer>
<p>AegisForge {_e(data["tool_version"])} — defensive-security and DFIR platform.
This document was generated from tool output; observations and inferences
are labelled separately throughout. Review before distribution.</p>
</footer>
</body>
</html>
"""
