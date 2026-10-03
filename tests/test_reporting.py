"""Tests for v1.0 professional reporting: data model, HTML/PDF/CSV,
CLI wiring and the CLI stability audit."""

from __future__ import annotations

import argparse
import csv
import io
import json
from contextlib import redirect_stdout
from html.parser import HTMLParser
from pathlib import Path

import pytest

from aegisforge.cases import store as store_mod
from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.reporting import exports as exports_mod
from aegisforge.reporting import html as html_mod
from aegisforge.reporting import model as model_mod
from aegisforge.reporting import pdf as pdf_mod
from aegisforge.reporting.exports import FORMATS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main.main(argv)
    return code, buf.getvalue()


@pytest.fixture()
def cases_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(state))
    return state


def _syslog(path: Path) -> Path:
    path.write_text(
        "Oct  3 01:05:01 web sshd[101]: Failed password for root from 203.0.113.7\n"
        "Oct  3 01:05:02 web sshd[102]: Accepted password for alice from 10.0.0.9\n",
        encoding="utf-8",
    )
    return path


def _burst_log(path: Path, lines: int = 12) -> Path:
    """Syslog that trips the auth brute-force finding (>=10 failures)."""
    body = "".join(
        f"Oct  3 01:05:{i:02d} web sshd[10{i}]: Failed password for root "
        f"from 203.0.113.7 port 5123{i} ssh2\n"
        for i in range(lines)
    )
    path.write_text(body, encoding="utf-8")
    return path


def _make_case(tmp_path: Path) -> str:
    log = _syslog(tmp_path / "auth.log")
    code, out = _run_cli(["case", "create", "--title", "Brute force"])
    assert code == 0
    case_id = out.strip().splitlines()[0].split()[1]
    code, _ = _run_cli(
        ["case", "attach", case_id, "--kind", "logs", "--source", str(log)]
    )
    assert code == 0
    code, _ = _run_cli(
        [
            "case",
            "finding",
            case_id,
            "--title",
            "Guessing from 203.0.113.7",
            "--severity",
            "high",
            "--confidence",
            "85",
            "--detail",
            "Failed logins cluster from one external IP.",
        ]
    )
    # Recording a finding is exit 1 (findings) by the CLI contract.
    assert code in (0, 1)
    code, _ = _run_cli(
        [
            "case",
            "link",
            case_id,
            "--finding",
            f"{case_id}-F01",
            "--indicator",
            "203.0.113.7",
        ]
    )
    assert code in (0, 1)
    code, _ = _run_cli(["case", "note", case_id, "Reviewed by analyst."])
    assert code == 0
    return case_id


def _case_data(case_id: str) -> dict:
    return model_mod.build_case_report_data(store_mod.load_case(case_id))


# ---------------------------------------------------------------------------
# Report data model
# ---------------------------------------------------------------------------


def test_case_report_data_has_every_section(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    for key in (
        "tool",
        "tool_version",
        "report_kind",
        "generated",
        "title",
        "case",
        "executive_summary",
        "evidence_inventory",
        "methodology",
        "findings",
        "timeline",
        "indicators",
        "analyst_notes",
        "supporting_evidence",
    ):
        assert key in data, f"missing section {key!r}"
    assert data["report_kind"] == "case"
    assert data["tool_version"] == "1.0.0"


def test_executive_summary_counts_match_case(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    case = store_mod.load_case(case_id)
    data = _case_data(case_id)
    summary = data["executive_summary"]
    assert summary["generated"] is True
    assert summary["analyst_review_required"] is True
    counts = summary["counts"]
    assert counts["evidence"] == len(case.evidence) == 1
    assert counts["findings"] == len(case.findings) == 1
    assert counts["timeline_entries"] == len(data["timeline"])
    assert counts["indicators"] == len(data["indicators"]) == 1
    assert summary["findings_by_severity"]["high"] == 1
    assert summary["date_range"]["start"] is not None
    assert summary["does_not_claim"], "not-claims box must not be empty"
    assert "analyst" in summary["paragraph"].lower()


def test_observed_inferred_labels_on_every_finding(
    tmp_path: Path, cases_home: Path
) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    assert data["findings"], "expected at least one finding"
    for finding in data["findings"]:
        assert finding["observed"]["label"] == "OBSERVED"
        assert finding["inferred"]["label"] == "INFERRED"
        assert finding["inferred"]["severity"] == "high"
        assert finding["inferred"]["confidence"] == 85
    # Linked indicator is observed, not inferred.
    indicators = data["findings"][0]["observed"]["indicators"]
    assert indicators[0]["value"] == "203.0.113.7"


def test_indicators_deduped_with_verdicts(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    values = [i["value"] for i in data["indicators"]]
    assert values == ["203.0.113.7"]
    indicator = data["indicators"][0]
    assert indicator["verdict"] == "unknown"  # no blocklist configured
    assert indicator["sources"] == [f"{case_id}-F01"]


def test_methodology_is_honest(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    by_module = {m["module"]: m for m in data["methodology"]}
    assert "logs" in by_module
    entry = by_module["logs"]
    assert entry["limitations"], "methodology must state limitations"
    assert entry["version"]  # filled from the plugin registry


def test_scan_report_data_sections(tmp_path: Path) -> None:
    log = _syslog(tmp_path / "auth.log")
    data = model_mod.build_scan_report_data(
        kind="logs",
        source_label=str(log),
        source_files=[{"path": str(log), "sha256": "abc", "size": 10}],
        findings=[],
        timeline=[],
        analysis_summary="1 event matched.",
    )
    assert data["report_kind"] == "scan"
    for key in (
        "executive_summary",
        "evidence_inventory",
        "methodology",
        "findings",
        "timeline",
        "indicators",
        "supporting_evidence",
    ):
        assert key in data
    assert "not enrich indicators" in data["indicators_note"]
    assert data["executive_summary"]["generated"] is True


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


class _TagChecker(HTMLParser):
    VOID = frozenset(
        {
            "meta",
            "br",
            "img",
            "link",
            "hr",
            "input",
            "area",
            "base",
            "col",
            "embed",
            "source",
            "track",
            "wbr",
        }
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.mismatches: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.VOID:
            return
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.mismatches.append(tag)


def test_html_is_valid_and_self_contained(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    text = html_mod.render_html(_case_data(case_id))
    checker = _TagChecker()
    checker.feed(text)
    assert checker.stack == [], f"unclosed tags: {checker.stack}"
    assert checker.mismatches == []
    assert "<style>" in text and "</style>" in text
    assert 'src="http' not in text and 'href="http' not in text
    assert "OBSERVED" in text and "INFERRED" in text
    assert "What this report does not claim" in text
    assert 'href="#findings"' in text  # anchored sections


# ---------------------------------------------------------------------------
# PDF renderer
# ---------------------------------------------------------------------------


def test_pdf_bytes_are_valid(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    raw = pdf_mod.render_pdf(_case_data(case_id))
    assert raw.startswith(b"%PDF-")
    assert raw.rstrip().endswith(b"%%EOF")
    assert case_id.encode("latin-1") in raw
    assert b"OBSERVED" in raw and b"INFERRED" in raw


def test_pdf_handles_long_report(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    # Pad the timeline so the PDF must paginate.
    data["timeline"] = data["timeline"] * 40
    raw = pdf_mod.render_pdf(data)
    assert raw.startswith(b"%PDF-")
    assert raw.count(b"/Type /Page ") >= 2 or b"/Count" in raw


# ---------------------------------------------------------------------------
# CSV / JSON exports
# ---------------------------------------------------------------------------


def test_csv_sections_have_headers(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    sections = exports_mod.csv_sections(_case_data(case_id))
    assert set(sections) == {
        "findings.csv",
        "timeline.csv",
        "evidence.csv",
        "indicators.csv",
    }
    headers = {
        name: next(csv.reader(io.StringIO(text))) for name, text in sections.items()
    }
    assert headers["findings.csv"][0] == "finding_id"
    assert "observed_label" in headers["findings.csv"]
    assert "inferred_label" in headers["findings.csv"]
    assert headers["timeline.csv"][0] == "timestamp"
    assert headers["evidence.csv"][0] == "evidence_id"
    assert "sha256" in headers["evidence.csv"]
    assert headers["indicators.csv"][0] == "value"
    assert "verdict" in headers["indicators.csv"]


def test_write_report_artifacts_and_manifest(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    out = tmp_path / "report"
    summary = exports_mod.write_report(data, str(out), formats=("all",))
    expected = {
        "report.html",
        "report.pdf",
        "report.json",
        "findings.csv",
        "timeline.csv",
        "evidence.csv",
        "indicators.csv",
        "report-manifest.json",
    }
    assert {p.name for p in out.iterdir()} == expected
    assert summary["artifact_count"] == len(expected)
    manifest = json.loads((out / "report-manifest.json").read_text())
    assert set(manifest["artifacts"]) == expected - {"report-manifest.json"}
    report_json = json.loads((out / "report.json").read_text())
    assert report_json["case"]["case_id"] == case_id


def test_write_report_single_format(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    out = tmp_path / "r"
    exports_mod.write_report(data, str(out), formats=("html",))
    assert {p.name for p in out.iterdir()} == {
        "report.html",
        "report-manifest.json",
    }


def test_write_report_refuses_nonempty_dir(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    data = _case_data(case_id)
    out = tmp_path / "r"
    out.mkdir()
    (out / "existing.txt").write_text("x")
    with pytest.raises(Exception, match="not empty"):
        exports_mod.write_report(data, str(out), formats=("json",))
    exports_mod.write_report(data, str(out), formats=("json",), force=True)
    assert (out / "report.json").exists()


def test_write_report_rejects_unknown_format(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    with pytest.raises(Exception, match="unknown report format"):
        exports_mod.write_report(
            _case_data(case_id), str(tmp_path / "r"), formats=("docx",)
        )


def test_formats_constant_matches_spec() -> None:
    assert set(FORMATS) == {"html", "pdf", "json", "csv", "all"}


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_report_case_cli(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    out = tmp_path / "report"
    code, text = _run_cli(
        ["report", "case", case_id, "--output", str(out), "--format", "all"]
    )
    assert code == 0, text
    assert (out / "report.html").exists()
    assert (out / "report.pdf").exists()
    assert "artifact(s)" in text


def test_report_case_cli_json_envelope(tmp_path: Path, cases_home: Path) -> None:
    case_id = _make_case(tmp_path)
    code, text = _run_cli(
        [
            "report",
            "case",
            case_id,
            "--output",
            str(tmp_path / "r"),
            "--format",
            "json",
            "--json",
        ]
    )
    assert code == 0
    envelope = json.loads(text)
    assert envelope["command"] == "report case"
    assert envelope["status"] == "ok"


def test_report_logs_cli(tmp_path: Path, cases_home: Path) -> None:
    log = _burst_log(tmp_path / "auth.log")
    out = tmp_path / "report"
    code, text = _run_cli(["report", "logs", "--file", str(log), "--output", str(out)])
    assert code == 0, text
    assert (out / "report.html").exists()
    data = json.loads((out / "report.json").read_text())
    assert data["report_kind"] == "scan"
    assert data["scan_kind"] == "logs"
    assert data["findings"], "burst log should produce findings"
    assert "OBSERVED" in (out / "report.html").read_text()


def test_report_pcap_cli(tmp_path: Path, cases_home: Path) -> None:
    import struct

    def tcp_packet() -> bytes:
        eth = b"\x00" * 12 + b"\x08\x00"  # dst+src MAC, IPv4 ethertype
        ip = struct.pack(
            ">BBHHHBBHII",
            0x45,
            0,
            40,
            0,
            0,
            64,
            6,
            0,
            0x0A000001,
            0x0A000002,
        )
        tcp = struct.pack(">HHIIHHHH", 12345, 80, 0, 0, 0x5002, 0, 0, 0)
        return eth + ip + tcp

    pcap = struct.pack(">I", 0xA1B2C3D4) + struct.pack(">HHIIII", 2, 4, 0, 0, 65535, 1)
    for i in range(3):
        pkt = tcp_packet()
        pcap += struct.pack(">IIII", 1_700_000_000 + i, 0, len(pkt), len(pkt)) + pkt
    path = tmp_path / "t.pcap"
    path.write_bytes(pcap)
    out = tmp_path / "report"
    code, text = _run_cli(["report", "pcap", "--file", str(path), "--output", str(out)])
    assert code == 0, text
    data = json.loads((out / "report.json").read_text())
    assert data["report_kind"] == "scan"
    assert data["scan_kind"] == "pcap"
    assert (out / "report.html").exists() and (out / "report.pdf").exists()


def test_report_forensics_cli(tmp_path: Path, cases_home: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_text("hello")
    out = tmp_path / "report"
    code, text = _run_cli(
        ["report", "forensics", "--path", str(root), "--output", str(out)]
    )
    assert code == 0, text
    data = json.loads((out / "report.json").read_text())
    assert data["scan_kind"] == "forensics"
    assert data["timeline"], "filesystem timestamps should be listed"


def test_report_case_unknown_case_fails(tmp_path: Path, cases_home: Path) -> None:
    code, _ = _run_cli(
        ["report", "case", "CASE-2099-999", "--output", str(tmp_path / "r")]
    )
    assert code == 2


def test_report_logs_missing_file_fails(tmp_path: Path, cases_home: Path) -> None:
    code, _ = _run_cli(
        ["report", "logs", "--file", "/no/such.log", "--output", str(tmp_path)]
    )
    assert code == 2


def test_version_command(tmp_path: Path, cases_home: Path) -> None:
    code, text = _run_cli(["version"])
    assert code == 0
    assert "aegisforge 1.0.0" in text
    assert "reporting: 1.0.0" in text


def test_version_flag() -> None:
    # argparse's action="version" exits via SystemExit, like --help.
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(["--version"])
    assert exc_info.value.code == 0


def test_version_json(tmp_path: Path, cases_home: Path) -> None:
    code, text = _run_cli(["version", "--json"])
    assert code == 0
    envelope = json.loads(text)
    assert envelope["data"]["version"] == "1.0.0"
    assert envelope["data"]["modules"]["reporting"] == "1.0.0"


def test_reporting_module_registered() -> None:
    registry = get_registry()
    info = registry.get("reporting")
    assert info.version == "1.0.0"
    assert "report case" in info.commands


# ---------------------------------------------------------------------------
# CLI stability audit: every leaf subcommand accepts --json/--csv
# ---------------------------------------------------------------------------


def _leaf_commands() -> list[tuple[tuple[str, ...], argparse.ArgumentParser]]:
    parser = cli_main.build_parser()
    found: list[tuple[tuple[str, ...], argparse.ArgumentParser]] = []

    def walk(p: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
        descended = False
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                descended = True
                for name, sub in action.choices.items():
                    walk(sub, path + (name,))
        if not descended:
            found.append((path, p))

    walk(parser, ())
    return found


_LEAVES = _leaf_commands()
assert len(_LEAVES) >= 50, "expected the full v1.0 command surface"


@pytest.mark.parametrize(
    "path", [path for path, _ in _LEAVES], ids=[" ".join(p) for p, _ in _LEAVES]
)
def test_every_subcommand_accepts_json_and_csv(
    path: tuple[str, ...],
) -> None:
    parser = dict(_LEAVES)[path]
    options = {opt for a in parser._actions for opt in a.option_strings}
    assert "--json" in options, f"{' '.join(path)} missing --json"
    assert "--csv" in options, f"{' '.join(path)} missing --csv"


def test_report_subcommands_exist() -> None:
    paths = {" ".join(p) for p, _ in _LEAVES}
    for cmd in (
        "report case",
        "report pcap",
        "report logs",
        "report forensics",
        "report domain",
        "version",
    ):
        assert cmd in paths, f"missing command {cmd}"
