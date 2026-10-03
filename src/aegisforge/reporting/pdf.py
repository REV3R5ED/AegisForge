"""Minimal stdlib-only PDF report renderer.

Writes a clean multi-page PDF 1.4 using only built-in Type1 fonts
(Helvetica / Helvetica-Bold / Courier) — no compression, no images, no
third-party libraries. It is a print-friendly *text* rendering of the
report, not a pixel-perfect layout: tables are monospaced text columns
and styling is limited to headings, bold and rules. This limitation is
documented in the user docs (the HTML report is the rich version).
"""

from __future__ import annotations

import textwrap
from typing import Any

PAGE_W, PAGE_H = 612, 792  # US Letter in points
MARGIN = 50
BODY_SIZE = 10
TABLE_SIZE = 8
MAX_Y = PAGE_H - MARGIN
MIN_Y = MARGIN + 20


def _sanitize(text: str) -> str:
    """Built-in Type1 fonts speak WinAnsi; replace what they cannot."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _esc(text: str) -> str:
    text = _sanitize(text)
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _Page:
    def __init__(self) -> None:
        self.ops: list[str] = []
        self.y = MAX_Y

    def _ensure(self, needed: float, doc: _Doc) -> _Page:
        if self.y - needed < MIN_Y:
            doc.new_page()
            return doc.current
        return self

    def _text(self, x: float, text: str, font: str, size: int) -> None:
        self.ops.append(
            f"BT /{font} {size} Tf {x:.1f} {self.y:.1f} Td ({_esc(text)}) Tj ET"
        )

    def heading(self, text: str, doc: _Doc) -> None:
        self._ensure(40, doc)
        page = doc.current
        page.y -= 8
        for line in textwrap.wrap(text, 60):
            page = page._ensure(22, doc)
            page._text(MARGIN, line, "F2", 14)
            page.y -= 20
        page.y -= 6

    def subheading(self, text: str, doc: _Doc) -> None:
        page = self._ensure(28, doc)
        page.y -= 4
        for line in textwrap.wrap(text, 80):
            page = page._ensure(18, doc)
            page._text(MARGIN, line, "F2", 11)
            page.y -= 15
        page.y -= 4

    def para(self, text: str, doc: _Doc, indent: float = 0) -> None:
        page = self._ensure(30, doc)
        for line in textwrap.wrap(text, 95) or [""]:
            page = page._ensure(15, doc)
            page._text(MARGIN + indent, line, "F1", BODY_SIZE)
            page.y -= 13
        page.y -= 4

    def bullet(self, text: str, doc: _Doc) -> None:
        page = self._ensure(30, doc)
        wrapped = textwrap.wrap(text, 90) or [""]
        page._text(MARGIN, "- " + wrapped[0], "F1", BODY_SIZE)
        page.y -= 13
        for line in wrapped[1:]:
            page = page._ensure(15, doc)
            page._text(MARGIN + 12, line, "F1", BODY_SIZE)
            page.y -= 13
        page.y -= 3

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        widths: list[int],
        doc: _Doc,
    ) -> None:
        """Monospaced table; widths are character counts per column."""
        char_w = TABLE_SIZE * 0.6
        xs: list[float] = []
        x: float = MARGIN
        for w in widths:
            xs.append(x)
            x += w * char_w + 8

        def row_lines(cells: list[str]) -> list[list[str]]:
            wrapped = [
                textwrap.wrap(c.replace("\n", " "), w) or [""]
                for c, w in zip(cells, widths, strict=False)
            ]
            height = max(len(w) for w in wrapped)
            return [list(w) + [""] * (height - len(w)) for w in wrapped]

        header = row_lines(headers)
        for li in range(len(header[0])):
            page = self._ensure(14, doc)
            for idx, (xi, col) in enumerate(zip(xs, header, strict=False)):
                page._text(xi, col[li][: widths[idx]], "F3", TABLE_SIZE)
            page.y -= 11
        page = doc.current
        page.y -= 2
        page.ops.append(f"{MARGIN:.1f} {page.y:.1f} m {x:.1f} {page.y:.1f} l S")
        page.y -= 6
        for cells in rows:
            wrapped = row_lines([str(c) for c in cells])
            for li in range(len(wrapped[0])):
                page = page._ensure(14, doc)
                for xi, col, w in zip(xs, wrapped, widths, strict=False):
                    page._text(xi, col[li][:w], "F3", TABLE_SIZE)
                page.y -= 11
            page.y -= 2


class _Doc:
    def __init__(self) -> None:
        self.pages: list[_Page] = [_Page()]

    @property
    def current(self) -> _Page:
        return self.pages[-1]

    def new_page(self) -> None:
        self.pages.append(_Page())


def _assemble(pages: list[_Page]) -> bytes:
    n_pages = len(pages)
    # Object numbering: 1 catalog, 2 pages, then per page (page, content),
    # then 3 fonts.
    page_obj_nums: list[tuple[int, int]] = []
    num = 3
    for _ in pages:
        page_obj_nums.append((num, num + 1))
        num += 2
    font_base = num
    fonts = {  # name -> (obj num, base font)
        "F1": (font_base, "Helvetica"),
        "F2": (font_base + 1, "Helvetica-Bold"),
        "F3": (font_base + 2, "Courier"),
    }

    kids = " ".join(f"{p} 0 R" for p, _ in page_obj_nums)
    objects: dict[int, bytes] = {}
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode("latin-1")
    for (pnum, cnum), page in zip(page_obj_nums, pages, strict=True):
        # Footer with page number.
        idx = page_obj_nums.index((pnum, cnum)) + 1
        page.ops.append(
            f"BT /F1 9 Tf {MARGIN:.1f} 32 Td "
            f"(AegisForge report - page {idx} of {n_pages}) Tj ET"
        )
        stream = "\n".join(page.ops).encode("latin-1")
        objects[pnum] = (
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 {fonts['F1'][0]} 0 R "
            f"/F2 {fonts['F2'][0]} 0 R /F3 {fonts['F3'][0]} 0 R >> >> "
            f"/Contents {cnum} 0 R >>".encode("latin-1")
        )
        objects[cnum] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream"
        )
    for _name, (fnum, base) in fonts.items():
        objects[fnum] = (
            f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} "
            f"/Encoding /WinAnsiEncoding >>".encode("latin-1")
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode("latin-1")
        out += objects[num] + b"\nendobj\n"
    xref_pos = len(out)
    size = max(objects) + 1
    out += f"xref\n0 {size}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, size):
        out += f"{offsets[num]:010d} 00000 n \n".encode("latin-1")
    out += (
        f"trailer\n<< /Size {size} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode("latin-1")
    )
    return bytes(out)


def render_pdf(data: dict[str, Any]) -> bytes:
    """Render the report data model as a multi-page PDF."""
    doc = _Doc()
    page = doc.current
    summary = data["executive_summary"]

    page.heading(data["title"], doc)
    page = doc.current
    if data.get("case"):
        page.para(
            f"Case {data['case']['case_id']} — {data['case']['title']} "
            f"({data['case']['status']})",
            doc,
        )
    elif data.get("source"):
        page.para(f"{data.get('scan_kind', 'scan')}: {data['source']['label']}", doc)
    page.para(
        f"Generated {data['generated']} by AegisForge {data['tool_version']} (UTC).",
        doc,
    )

    page = doc.current
    page.subheading("Executive summary", doc)
    page = doc.current
    page.para(
        "AUTO-GENERATED: this text was produced by AegisForge from the "
        "data below and must be reviewed by an analyst before distribution.",
        doc,
    )
    page = doc.current
    page.para(summary["paragraph"], doc)
    page = doc.current
    if summary["top_findings"]:
        page.subheading("Top findings", doc)
        page = doc.current
        page.table(
            ["Finding", "Severity", "Conf"],
            [
                [t["title"], t["severity"], f"{t['confidence']}"]
                for t in summary["top_findings"]
            ],
            [62, 12, 8],
            doc,
        )
    page = doc.current
    page.subheading("What this report does not claim", doc)
    page = doc.current
    for claim in summary["does_not_claim"]:
        page.bullet(claim, doc)
        page = doc.current

    page = doc.current
    page.subheading("Evidence inventory", doc)
    page = doc.current
    if data["evidence_inventory"]:
        page.table(
            ["ID", "Kind", "Original path", "SHA-256 (trunc)", "Size"],
            [
                [
                    e["evidence_id"],
                    e["kind"],
                    e["original_path"],
                    (e["sha256"] or "")[:32],
                    str(e["size"]),
                ]
                for e in data["evidence_inventory"]
            ],
            [14, 8, 40, 34, 8],
            doc,
        )
    else:
        page.para("No evidence items.", doc)

    page = doc.current
    page.subheading("Methodology", doc)
    page = doc.current
    for m in data["methodology"]:
        page.para(
            f"{m['module']} v{m['version']}: {m['purpose']} "
            f"Method: {m['method']} Limitations: {m['limitations']}",
            doc,
        )
        page = doc.current

    page = doc.current
    page.subheading("Findings (observed vs inferred)", doc)
    page = doc.current
    for f in data["findings"]:
        obs, inf = f["observed"], f["inferred"]
        page.para(
            f"{f['title']} [{inf['severity'].upper()}, "
            f"confidence {inf['confidence']}/100] ({f['finding_id']})",
            doc,
        )
        page = doc.current
        page.para("OBSERVED:", doc)
        page = doc.current
        for ev in obs.get("evidence", []):
            page.bullet(str(ev), doc)
            page = doc.current
        for ind in obs.get("indicators", []):
            page.bullet(
                f"{ind['value']} ({ind['type']}, type {ind['type_source']})",
                doc,
            )
            page = doc.current
        page.para("INFERRED: " + (inf.get("reason") or inf.get("detail") or ""), doc)
        page = doc.current
        page.para(f"Note: {inf.get('note', '')}", doc)
        page = doc.current
    if not data["findings"]:
        page.para("No findings recorded.", doc)
        page = doc.current

    page = doc.current
    page.subheading("Timeline", doc)
    page = doc.current
    if data["timeline"]:
        page.table(
            ["Timestamp (UTC)", "Source", "Summary"],
            [
                [
                    e["timestamp"] or "(untimed)",
                    e["source"],
                    e["summary"],
                ]
                for e in data["timeline"]
            ],
            [24, 22, 56],
            doc,
        )
    else:
        page.para("No timeline entries.", doc)

    page = doc.current
    page.subheading("Indicators", doc)
    page = doc.current
    if data.get("indicators_note"):
        page.para(data["indicators_note"], doc)
        page = doc.current
    if data["indicators"]:
        page.table(
            ["Indicator", "Type", "Verdict", "Source"],
            [
                [i["value"], i["type"], i["verdict"], i["verdict_source"]]
                for i in data["indicators"]
            ],
            [40, 10, 12, 40],
            doc,
        )
    else:
        page.para("No indicators.", doc)

    page = doc.current
    page.subheading("Supporting evidence and hashes", doc)
    page = doc.current
    if data["supporting_evidence"]:
        page.table(
            ["Label", "SHA-256"],
            [
                [s["label"], s["sha256"] or "(none)"]
                for s in data["supporting_evidence"]
            ],
            [30, 66],
            doc,
        )
    else:
        page.para("None.", doc)

    return _assemble(doc.pages)
