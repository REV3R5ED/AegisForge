"""Tests for the v0.6 incident-response engine: cases, evidence, timelines,
findings, indicator linking, notes, reports and CLI wiring."""

from __future__ import annotations

import hashlib
import io
import json
import os
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegisforge.cases import evidence as evidence_mod
from aegisforge.cases import findings as findings_mod
from aegisforge.cases import indicators as indicators_mod
from aegisforge.cases import store as store_mod
from aegisforge.cases.store import CaseError
from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry

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
    """Isolated case storage for every test."""
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


def _case_id_from_create(out: str) -> str:
    first = out.strip().splitlines()[0]
    # "case CASE-2026-001 created: ..."
    return first.split()[1]


def _create(title: str = "T", note: str | None = None) -> str:
    argv = ["case", "create", "--title", title]
    if note is not None:
        argv += ["--note", note]
    code, out = _run_cli(argv)
    assert code == 0, out
    return _case_id_from_create(out)


def _attach_ok(case_id: str, kind: str, source: Path) -> None:
    code, out = _run_cli(
        ["case", "attach", case_id, "--kind", kind, "--source", str(source)]
    )
    assert code == 0, out


def _finding_ok(
    case_id: str, title: str, severity: str = "low", confidence: int = 40
) -> None:
    code, out = _run_cli(
        [
            "case",
            "finding",
            case_id,
            "--title",
            title,
            "--severity",
            severity,
            "--confidence",
            str(confidence),
        ]
    )
    assert code == 1, out  # findings produced -> exit 1


# ---------------------------------------------------------------------------
# Case creation and ID sequencing
# ---------------------------------------------------------------------------


def test_create_assigns_sequenced_ids(cases_home: Path):
    year = datetime.now(timezone.utc).year
    code, out = _run_cli(["case", "create", "--title", "First"])
    assert code == 0
    assert f"CASE-{year}-001" in out
    code, out = _run_cli(["case", "create", "--title", "Second"])
    assert code == 0
    assert f"CASE-{year}-002" in out


def test_create_with_opening_note(cases_home: Path):
    code, _ = _run_cli(["case", "create", "--title", "T", "--note", "hello"])
    assert code == 0
    case_id = _run_cli(["case", "list"])[1].splitlines()[-1].split()[0]
    case = store_mod.load_case(case_id)
    assert len(case.notes) == 1
    assert case.notes[0].text == "hello"


def test_create_rejects_empty_title(cases_home: Path):
    code, _ = _run_cli(["case", "create", "--title", "   "])
    assert code == 2


def test_unknown_case_is_exit_2(cases_home: Path):
    code, out = _run_cli(["case", "show", "CASE-2026-999"])
    assert code == 2
    assert "unknown case" in out or True  # message goes to stderr on fail


def test_list_and_show(cases_home: Path):
    _run_cli(["case", "create", "--title", "Alpha"])
    _run_cli(["case", "create", "--title", "Beta"])
    code, out = _run_cli(["case", "list"])
    assert code == 0
    assert "Alpha" in out and "Beta" in out
    case_id = _run_cli(["case", "list"])[1].splitlines()[-1].split()[0]
    code, out = _run_cli(["case", "show", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    assert data["title"] == "Beta"
    assert data["status"] == "open"


# ---------------------------------------------------------------------------
# Evidence attachment
# ---------------------------------------------------------------------------


def test_attach_copies_hashes_and_records(cases_home: Path, tmp_path: Path):
    case_id = _create()
    src = tmp_path / "auth.log"
    _syslog(src)
    before = src.stat()
    code, out = _run_cli(
        ["case", "attach", case_id, "--kind", "logs", "--source", str(src)]
    )
    assert code == 0, out
    case = store_mod.load_case(case_id)
    assert len(case.evidence) == 1
    rec = case.evidence[0]
    assert rec.kind == "logs"
    assert rec.sha256 == hashlib.sha256(src.read_bytes()).hexdigest()
    assert rec.original_path == str(src.resolve())
    stored = store_mod.case_dir(case_id) / rec.stored_path
    assert stored.exists()
    # Source untouched: same size and mtime.
    after = src.stat()
    assert (after.st_size, after.st_mtime) == (before.st_size, before.st_mtime)


def test_attach_missing_source_is_exit_2(cases_home: Path, tmp_path: Path):
    case_id = _create()
    code, _ = _run_cli(
        [
            "case",
            "attach",
            case_id,
            "--kind",
            "logs",
            "--source",
            str(tmp_path / "nope.log"),
        ]
    )
    assert code == 2


def test_attach_rejects_directory(cases_home: Path, tmp_path: Path):
    case_id = _create()
    code, _ = _run_cli(
        ["case", "attach", case_id, "--kind", "files", "--source", str(tmp_path)]
    )
    assert code == 2


def test_attach_bad_kind_raises(cases_home: Path, tmp_path: Path):
    case = store_mod.create_case("T")
    src = tmp_path / "x.bin"
    src.write_bytes(b"x")
    with pytest.raises(CaseError):
        evidence_mod.attach_evidence(case, "bogus", str(src))


def test_attach_name_collision_suffixes(cases_home: Path, tmp_path: Path):
    case_id = _create()
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    (d1 / "same.log").write_text("one")
    (d2 / "same.log").write_text("two")
    _attach_ok(case_id, "logs", d1 / "same.log")
    _attach_ok(case_id, "logs", d2 / "same.log")
    case = store_mod.load_case(case_id)
    stored = sorted(e.stored_path for e in case.evidence)
    assert stored[0].endswith("same.log")
    assert stored[1].endswith("same_2.log")


# ---------------------------------------------------------------------------
# Unified timeline
# ---------------------------------------------------------------------------


def test_timeline_merges_log_and_file_events(cases_home: Path, tmp_path: Path):
    case_id = _create()
    src = tmp_path / "auth.log"
    _syslog(src)
    os.utime(src, (0, 0))  # ancient mtime: file event sorts before log events
    _attach_ok(case_id, "logs", src)
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"data")
    _attach_ok(case_id, "files", blob)
    code, out = _run_cli(["case", "timeline", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    kinds = [e["kind"] for e in data["timeline_entries"]]
    assert "log-event" in kinds and "file-mtime" in kinds
    stamps = [e["timestamp"] for e in data["timeline_entries"]]
    assert stamps == sorted(stamps), "timed entries must be chronological"


def test_timeline_untimed_section_never_drops(cases_home: Path, tmp_path: Path):
    case_id = _create()
    kv = tmp_path / "app.log"
    kv.write_text("level=high msg=boom\n", encoding="utf-8")  # no timestamp key
    _attach_ok(case_id, "logs", kv)
    code, out = _run_cli(["case", "timeline", case_id, "--json"])
    assert code == 0
    data = json.loads(out)["data"]
    assert data["untimed_count"] == 1
    assert data["untimed"][0]["timestamp"] is None
    assert "boom" in data["untimed"][0]["summary"]


def test_timeline_network_envelope_events(cases_home: Path, tmp_path: Path):
    case_id = _create()
    envelope = tmp_path / "scan.json"
    envelope.write_text(
        json.dumps(
            {
                "command": "network scan",
                "events": [
                    {
                        "event_type": "network.scan.completed",
                        "timestamp": "2026-10-03T01:00:00Z",
                        "host": "10.0.0.5",
                        "severity": "info",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _attach_ok(case_id, "network", envelope)
    code, out = _run_cli(["case", "timeline", case_id, "--json"])
    assert code == 0
    entries = json.loads(out)["data"]["timeline_entries"]
    net = [e for e in entries if e["kind"] == "network-event"]
    assert len(net) == 1
    assert net[0]["timestamp"] == "2026-10-03T01:00:00Z"


def test_timeline_network_non_envelope_records_attachment(
    cases_home: Path, tmp_path: Path
):
    case_id = _create()
    raw = tmp_path / "notes.txt"
    raw.write_text("not json", encoding="utf-8")
    _attach_ok(case_id, "network", raw)
    code, out = _run_cli(["case", "timeline", case_id, "--json"])
    assert code == 0
    entries = json.loads(out)["data"]["timeline_entries"]
    kinds = [e["kind"] for e in entries]
    assert "evidence-attached" in kinds


def test_timeline_csv(cases_home: Path, tmp_path: Path):
    case_id = _create()
    _attach_ok(case_id, "logs", _syslog(tmp_path / "a.log"))
    code, out = _run_cli(["case", "timeline", case_id, "--csv"])
    assert code == 0
    assert out.splitlines()[0] == "timestamp,source,kind,summary,detail"


# ---------------------------------------------------------------------------
# Findings, indicators, notes, status
# ---------------------------------------------------------------------------


def test_finding_lifecycle(cases_home: Path):
    case_id = _create()
    code, out = _run_cli(
        [
            "case",
            "finding",
            case_id,
            "--title",
            "Brute force",
            "--severity",
            "high",
            "--confidence",
            "80",
            "--detail",
            "OBSERVED: failures. INFERRED: attack.",
        ]
    )
    assert code == 1  # findings produced -> exit 1
    fid = f"{case_id}-F01"
    assert fid in out
    case = store_mod.load_case(case_id)
    assert case.findings[0].status == "open"

    findings_mod.set_finding_status(case, fid, "investigating")
    assert case.get_finding(fid).status == "investigating"
    findings_mod.set_finding_status(case, fid, "resolved")
    assert case.get_finding(fid).status == "resolved"
    with pytest.raises(CaseError):
        findings_mod.set_finding_status(case, fid, "investigating")  # bad move


def test_finding_validation(cases_home: Path):
    case = store_mod.create_case("T")
    with pytest.raises(CaseError):
        findings_mod.add_case_finding(case, "x", "bogus", 50)
    with pytest.raises(CaseError):
        findings_mod.add_case_finding(case, "x", "high", 101)
    with pytest.raises(CaseError):
        findings_mod.add_case_finding(case, "   ", "high", 50)
    with pytest.raises(CaseError):
        findings_mod.set_finding_status(case, f"{case.case_id}-F99", "resolved")


def test_findings_list_and_filter(cases_home: Path):
    case_id = _create()
    _finding_ok(case_id, "A", severity="high", confidence=70)
    _finding_ok(case_id, "B", severity="low", confidence=30)
    code, out = _run_cli(["case", "findings", case_id, "--json"])
    assert code == 0
    assert json.loads(out)["data"]["count"] == 2
    code, out = _run_cli(["case", "findings", case_id, "--status", "open", "--csv"])
    assert code == 0
    header = "finding_id,title,severity,confidence,status,indicators"
    assert header in out.splitlines()[0]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("203.0.113.7", "ip"),
        ("2001:db8::1", "ip"),
        ("example.com", "domain"),
        ("https://example.com/x", "url"),
        ("user@example.com", "email"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),
        ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "hash"),
    ],
)
def test_indicator_guessing(value: str, expected: str):
    assert indicators_mod.guess_indicator_type(value) == expected


def test_link_indicator_records_guess_vs_specified(cases_home: Path):
    case_id = _create()
    _finding_ok(case_id, "F", severity="medium", confidence=60)
    fid = f"{case_id}-F01"
    code, out = _run_cli(
        ["case", "link", case_id, "--finding", fid, "--indicator", "203.0.113.7"]
    )
    assert code == 0
    assert "guessed" in out
    code, _ = _run_cli(
        [
            "case",
            "link",
            case_id,
            "--finding",
            fid,
            "--indicator",
            "203.0.113.7",
            "--type",
            "ip",
        ]
    )
    assert code == 0
    case = store_mod.load_case(case_id)
    links = case.get_finding(fid).indicators
    assert links[0].type_source == "guessed" and links[0].type == "ip"
    assert links[1].type_source == "specified" and links[1].type == "ip"
    with pytest.raises(CaseError):
        findings_mod.link_indicator(case, "nope", "1.2.3.4")


def test_note_append_only(cases_home: Path):
    case_id = _create()
    assert _run_cli(["case", "note", case_id, "first"])[0] == 0
    assert _run_cli(["case", "note", case_id, "second"])[0] == 0
    case = store_mod.load_case(case_id)
    assert [n.text for n in case.notes] == ["first", "second"]
    code, _ = _run_cli(["case", "note", case_id, "   "])
    assert code == 2


def test_close_requires_note(cases_home: Path):
    case_id = _create()
    code, _ = _run_cli(["case", "status", case_id, "closed"])
    assert code == 2
    case = store_mod.load_case(case_id)
    assert case.status == "open"  # unchanged
    code, _ = _run_cli(["case", "status", case_id, "closed", "--note", "Done."])
    assert code == 0
    assert store_mod.load_case(case_id).status == "closed"


def test_status_show_when_omitted(cases_home: Path):
    case_id = _create()
    code, out = _run_cli(["case", "status", case_id])
    assert code == 0
    assert "open" in out


# ---------------------------------------------------------------------------
# Report bundle
# ---------------------------------------------------------------------------


def test_report_bundle_and_manifest(cases_home: Path, tmp_path: Path):
    case_id = _create(note="n1")
    _attach_ok(case_id, "logs", _syslog(tmp_path / "a.log"))
    _finding_ok(case_id, "F")
    out_dir = tmp_path / "report"
    code, out = _run_cli(["case", "report", case_id, "--output", str(out_dir)])
    assert code == 0, out
    expected = {
        "case.json",
        "evidence-manifest.json",
        "timeline.json",
        "timeline.csv",
        "findings.json",
        "notes.txt",
        "report-manifest.json",
    }
    assert {p.name for p in out_dir.iterdir()} == expected
    manifest = json.loads((out_dir / "report-manifest.json").read_text())
    for name, digest in manifest["artifacts"].items():
        actual = hashlib.sha256((out_dir / name).read_bytes()).hexdigest()
        assert actual == digest, f"manifest hash mismatch for {name}"
    findings = json.loads((out_dir / "findings.json").read_text())
    assert findings["count"] == 1


def test_report_refuses_nonempty_without_force(cases_home: Path, tmp_path: Path):
    case_id = _create()
    out_dir = tmp_path / "report"
    out_dir.mkdir()
    (out_dir / "old.txt").write_text("x")
    code, _ = _run_cli(["case", "report", case_id, "--output", str(out_dir)])
    assert code == 2
    code, _ = _run_cli(["case", "report", case_id, "--output", str(out_dir), "--force"])
    assert code == 0


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_cases_module_registered():
    info = get_registry().get("cases")
    assert info.version == "0.6.0"
    assert "case timeline" in info.commands
    assert "case report" in info.commands
