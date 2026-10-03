"""Tests for the v0.4 log analysis module: parsers, detection, filters,
analysis, redaction, streaming, and CLI wiring."""

import json
import tracemalloc

import pytest

from aegisforge.cli import main as cli_main
from aegisforge.core.plugins import get_registry
from aegisforge.logs import detect as detect_mod
from aegisforge.logs.analyze import (
    AnalyzeOptions,
    analyze_events,
    analyze_file,
    detect_bursts,
)
from aegisforge.logs.filters import LogFilter
from aegisforge.logs.models import LogEvent, ParseWarning
from aegisforge.logs.parsers import (
    ApacheParser,
    JsonLinesParser,
    KeyValueParser,
    SyslogParser,
    WindowsXmlParser,
    get_parser,
    iter_parsed_file,
    parse_iso_timestamp,
)
from aegisforge.logs.redact import redact_text, redact_value
from aegisforge.network.validation import ValidationError

SYSLOG_SAMPLE = [
    "<34>Oct  2 16:00:01 web1 sshd[101]: Failed password for root "
    "from 203.0.113.7 port 51234 ssh2",
    "Oct  2 16:05:00 web1 sshd[200]: Accepted password for deploy "
    "from 198.51.100.23 port 44000 ssh2",
    "<165>1 2026-10-02T16:47:04.123Z web1 myapp 42 - "
    '[exampleSDID@123 a="b"] hello world',
    "this line is malformed",
]

APACHE_SAMPLE = [
    "203.0.113.7 - frank [02/Oct/2026:16:00:01 +0000] "
    '"GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"',
    '203.0.113.8 - - [02/Oct/2026:16:00:02 +0000] "POST /login HTTP/1.1" 500 0 "-" "-"',
    '203.0.113.9 - - [02/Oct/2026:16:00:03 +0000] "GET /missing HTTP/1.1" 404 12',
    "garbage line here",
]

JSON_SAMPLE = [
    '{"timestamp": "2026-10-02T16:00:01Z", "level": "error", '
    '"host": "web1", "msg": "disk full", "user": "admin@example.com"}',
    '{"ts": 1759420801, "level": "info", "host": "web2", "message": "started"}',
    "not json at all",
    "[1, 2, 3]",
]

XML_SAMPLE = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-10-02T16:00:01.1234567Z"/>
    <Computer>DC01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">203.0.113.7</Data>
  </EventData>
</Event>
</Events>
""".splitlines(keepends=True)

KV_SAMPLE = [
    'ts=2026-10-02T16:00:01Z level=error host=web1 msg="disk full on /var"',
    "level=info host=web2 msg=started",
    "plain prose without pairs",
]


def _parse_all(parser, lines):
    events, warnings = [], []
    for item in parser.parse_lines(lines):
        (events if isinstance(item, LogEvent) else warnings).append(item)
    return events, warnings


# ---------------------------------------------------------------------------
# Syslog parser
# ---------------------------------------------------------------------------


def test_syslog_rfc3164_fields():
    events, warnings = _parse_all(SyslogParser(), SYSLOG_SAMPLE[:2])
    assert not warnings
    first, second = events
    assert first.timestamp == "2026-10-02T16:00:01Z" or first.timestamp.endswith("Z")
    assert first.host == "web1"
    assert first.fields["process"] == "sshd"
    assert first.fields["pid"] == "101"
    assert first.fields["facility"] == 4  # 34 >> 3
    # pri 34 -> severity 2 (crit) -> high
    assert first.severity == "high"
    # No PRI -> info
    assert second.severity == "info"
    assert "Failed password" in first.message


def test_syslog_rfc5424_structured_data():
    events, warnings = _parse_all(SyslogParser(), SYSLOG_SAMPLE[2:3])
    assert not warnings
    event = events[0]
    assert event.timestamp == "2026-10-02T16:47:04.123000Z"
    assert event.fields["app"] == "myapp"
    assert event.fields["structured_data"] == '[exampleSDID@123 a="b"]'
    assert event.message == "hello world"


def test_syslog_malformed_becomes_warning():
    events, warnings = _parse_all(SyslogParser(), SYSLOG_SAMPLE[3:4])
    assert not events
    assert len(warnings) == 1
    assert warnings[0].line_number == 1
    assert warnings[0].reason


def test_syslog_unterminated_structured_data_warns():
    events, warnings = _parse_all(
        SyslogParser(), ["<165>1 2026-10-02T16:47:04Z h app 1 - [oops no close"]
    )
    assert not events
    assert warnings and "structured data" in warnings[0].reason


# ---------------------------------------------------------------------------
# Apache parser
# ---------------------------------------------------------------------------


def test_apache_combined_and_common():
    events, warnings = _parse_all(ApacheParser(), APACHE_SAMPLE[:3])
    assert not warnings
    ok, err, missing = events
    assert ok.fields["method"] == "GET"
    assert ok.fields["path"] == "/index.html"
    assert ok.fields["status"] == 200
    assert ok.severity == "info"
    assert ok.host == "203.0.113.7"
    assert err.fields["status"] == 500
    assert err.severity == "high"
    assert missing.severity == "medium"  # 404
    assert ok.timestamp == "2026-10-02T16:00:01Z"


def test_apache_malformed_becomes_warning():
    events, warnings = _parse_all(ApacheParser(), APACHE_SAMPLE[3:4])
    assert not events
    assert len(warnings) == 1


# ---------------------------------------------------------------------------
# JSON lines parser
# ---------------------------------------------------------------------------


def test_json_lines_fields():
    events, warnings = _parse_all(JsonLinesParser(), JSON_SAMPLE[:2])
    assert not warnings
    first, second = events
    assert first.timestamp == "2026-10-02T16:00:01Z"
    assert first.severity == "high"
    assert first.host == "web1"
    assert first.message == "disk full"
    assert first.fields["user"] == "admin@example.com"
    # epoch timestamp + alternate keys
    assert second.timestamp is not None and second.timestamp.endswith("Z")
    assert second.severity == "info"


def test_json_lines_malformed_become_warnings():
    events, warnings = _parse_all(JsonLinesParser(), JSON_SAMPLE[2:4])
    assert not events
    assert len(warnings) == 2
    assert "invalid JSON" in warnings[0].reason
    assert "not an object" in warnings[1].reason


# ---------------------------------------------------------------------------
# Windows Event XML parser
# ---------------------------------------------------------------------------


def test_iso_timestamp_truncates_long_fractional_seconds():
    # Windows/.NET timestamps carry 7 fractional digits; Python < 3.11
    # fromisoformat only accepts 3 or 6. Truncate to microseconds so
    # parsing behaves identically on 3.10–3.13.
    assert (
        parse_iso_timestamp("2026-10-02T16:00:01.1234567Z")
        == "2026-10-02T16:00:01.123456Z"
    )
    assert (
        parse_iso_timestamp("2026-10-02T16:00:01.123456Z")
        == "2026-10-02T16:00:01.123456Z"
    )
    assert (
        parse_iso_timestamp("2026-10-02T16:00:01.123Z") == "2026-10-02T16:00:01.123000Z"
    )
    assert parse_iso_timestamp("not-a-timestamp") is None


def test_winevent_xml_fragment():
    events, warnings = _parse_all(WindowsXmlParser(), XML_SAMPLE)
    assert not warnings, [w.reason for w in warnings]
    assert len(events) == 1
    event = events[0]
    assert event.fields["event_id"] == "4625"
    assert event.severity == "high"  # Level 2 = error
    assert event.host == "DC01"
    assert event.timestamp.startswith("2026-10-02T16:00:01")
    assert event.fields["targetusername"] == "admin"
    assert event.fields["ipaddress"] == "203.0.113.7"
    assert "4625" in event.message


def test_winevent_single_line_event():
    line = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4624</EventID><Level>4</Level>"
        '<TimeCreated SystemTime="2026-10-02T16:00:01Z"/>'
        "<Computer>DC01</Computer></System></Event>"
    )
    events, warnings = _parse_all(WindowsXmlParser(), [line])
    assert not warnings
    assert events[0].severity == "info"
    assert events[0].fields["event_id"] == "4624"


def test_winevent_bad_xml_warns():
    events, warnings = _parse_all(WindowsXmlParser(), ["<Event><System><oops></Event>"])
    assert not events
    assert warnings and "invalid event XML" in warnings[0].reason


def test_winevent_unterminated_warns():
    events, warnings = _parse_all(
        WindowsXmlParser(), ['<Event xmlns="urn:x">', "  <System>"]
    )
    assert not events
    assert warnings and "unterminated" in warnings[0].reason


# ---------------------------------------------------------------------------
# Key=value parser
# ---------------------------------------------------------------------------


def test_keyvalue_fields():
    events, warnings = _parse_all(KeyValueParser(), KV_SAMPLE[:2])
    assert not warnings
    first, second = events
    assert first.timestamp == "2026-10-02T16:00:01Z"
    assert first.severity == "high"
    assert first.host == "web1"
    assert first.message == "disk full on /var"
    assert second.message == "started"
    assert second.severity == "info"


def test_keyvalue_no_pairs_warns():
    events, warnings = _parse_all(KeyValueParser(), KV_SAMPLE[2:3])
    assert not events
    assert len(warnings) == 1


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------


def test_detect_each_format():
    assert detect_mod.detect_lines(SYSLOG_SAMPLE).parser == "syslog"
    assert detect_mod.detect_lines(APACHE_SAMPLE).parser == "apache"
    assert detect_mod.detect_lines(JSON_SAMPLE).parser == "json"
    assert detect_mod.detect_lines(XML_SAMPLE).parser == "winevent"
    assert detect_mod.detect_lines(KV_SAMPLE).parser == "keyvalue"


def test_detect_confidence_and_scores_reported():
    result = detect_mod.detect_lines(SYSLOG_SAMPLE)
    assert 0.0 < result.confidence <= 1.0
    assert set(result.scores) == {
        "syslog",
        "apache",
        "json",
        "winevent",
        "keyvalue",
    }
    assert result.lines_sampled == len(SYSLOG_SAMPLE)


def test_detect_unknown_for_garbage():
    result = detect_mod.detect_lines(
        ["hello world", "just some prose", "nothing structured here at all"]
    )
    assert result.parser == "unknown"
    assert result.confidence == 0.0


def test_detect_file(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("\n".join(APACHE_SAMPLE[:3]) + "\n")
    result = detect_mod.detect_file(str(path))
    assert result.parser == "apache"
    assert result.confidence > 0.9


def test_get_parser_names():
    assert get_parser("syslog").name == "syslog"
    with pytest.raises(KeyError):
        get_parser("bogus")


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def _event(**kwargs):
    base = dict(
        message="hello",
        timestamp="2026-10-02T16:00:01Z",
        parser="syslog",
        host="web1",
        severity="info",
    )
    base.update(kwargs)
    return LogEvent(**base)


def test_filter_levels_and_contains():
    filt = LogFilter(levels=("high",), contains=("password",)).resolve()
    assert filt.matches(_event(severity="high", message="Failed password"))
    assert not filt.matches(_event(severity="info", message="Failed password"))
    assert not filt.matches(_event(severity="high", message="something else"))


def test_filter_not_contains_and_host():
    filt = LogFilter(not_contains=("healthcheck",), host="web1").resolve()
    assert filt.matches(_event(message="GET /index"))
    assert not filt.matches(_event(message="GET /healthcheck"))
    assert not filt.matches(_event(host="web2"))


def test_filter_time_bounds():
    filt = LogFilter(
        since="2026-10-02T16:00:00Z", until="2026-10-02T17:00:00Z"
    ).resolve()
    assert filt.matches(_event(timestamp="2026-10-02T16:30:00Z"))
    assert not filt.matches(_event(timestamp="2026-10-02T18:00:00Z"))
    assert not filt.matches(_event(timestamp=None))  # timeless excluded


def test_filter_bad_timestamp_raises():
    with pytest.raises(ValueError):
        LogFilter(since="not-a-time").resolve()


def test_filter_describe_only_active():
    desc = LogFilter(host="web1", limit=10).resolve().describe()
    assert desc == {"host": "web1", "limit": 10}


# ---------------------------------------------------------------------------
# Burst detection + analysis
# ---------------------------------------------------------------------------


def _auth_log_lines(count=12, ip="203.0.113.7"):
    lines = []
    for i in range(count):
        lines.append(
            f"Oct  2 16:00:{i:02d} web1 sshd[{100 + i}]: "
            f"Failed password for root from {ip} port {50000 + i} ssh2"
        )
    lines.append(
        "Oct  2 16:05:00 web1 sshd[200]: Accepted password for deploy "
        "from 198.51.100.23 port 44000 ssh2"
    )
    lines.append("this line is malformed")
    return lines


def test_analyze_auth_burst_finding(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(_auth_log_lines()) + "\n")
    filt = LogFilter().resolve()
    result = analyze_file(str(path), filt, AnalyzeOptions())
    assert result.parser == "syslog"
    assert result.events_matched == 13
    assert result.warning_count == 1
    assert result.top_ips[0] == ["203.0.113.7", 12]
    assert result.top_hosts[0] == ["web1", 13]
    assert result.time_first == "2026-10-02T16:00:00Z"
    assert result.time_last == "2026-10-02T16:05:00Z"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "authentication-failure burst" in finding.title
    assert finding.severity == "medium"
    # Observed-vs-inferred discipline: both labels present.
    assert "OBSERVED" in finding.reason
    assert "INFERRED" in finding.reason
    assert "brute-force" in finding.reason


def test_analyze_5xx_spike_finding(tmp_path):
    lines = []
    for i in range(25):
        lines.append(
            f"203.0.113.7 - - [02/Oct/2026:16:00:{i:02d} +0000] "
            f'"GET /app HTTP/1.1" 503 12 "-" "-"'
        )
    path = tmp_path / "access.log"
    path.write_text("\n".join(lines) + "\n")
    result = analyze_file(
        str(path),
        LogFilter().resolve(),
        AnalyzeOptions(http_5xx_threshold=20),
    )
    assert result.status_histogram.get("503") == 25
    spikes = [f for f in result.findings if "5xx" in f.title]
    assert len(spikes) == 1
    assert "OBSERVED" in spikes[0].reason and "INFERRED" in spikes[0].reason


def test_analyze_exception_cluster(tmp_path):
    lines = [
        "Oct  2 16:00:01 web1 app[1]: starting up",
    ]
    for minute in range(2, 8):
        lines.append(
            f"Oct  2 16:{minute:02d}:02 web1 app[1]: "
            "Traceback (most recent call last): ValueError: bad config"
        )
    path = tmp_path / "app.log"
    path.write_text("\n".join(lines) + "\n")
    result = analyze_file(
        str(path),
        LogFilter().resolve(),
        AnalyzeOptions(exception_cluster_threshold=5),
    )
    clusters = [f for f in result.findings if "exception cluster" in f.title]
    assert len(clusters) == 1
    assert "6 occurrences" in clusters[0].title


def test_analyze_errors_with_context(tmp_path):
    lines = [
        "Oct  2 16:00:01 web1 app[1]: normal line one",
        "Oct  2 16:00:02 web1 app[1]: normal line two",
        # pri 11 -> severity 3 (err) -> high
        "<11>Oct  2 16:00:03 web1 app[1]: disk failure imminent",
        "Oct  2 16:00:04 web1 app[1]: normal line three",
    ]
    path = tmp_path / "app.log"
    path.write_text("\n".join(lines) + "\n")
    result = analyze_file(
        str(path), LogFilter().resolve(), AnalyzeOptions(context_lines=2)
    )
    assert len(result.errors) == 1
    entry = result.errors[0]
    assert entry["event"]["line_number"] == 3
    assert any("normal line two" in ctx for ctx in entry["context_before"])
    assert any("normal line three" in ctx for ctx in entry["context_after"])


def test_analyze_winevent_auth_failures(tmp_path):
    events = []
    for i in range(11):
        events.append(
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4625</EventID><Level>2</Level>"
            f'<TimeCreated SystemTime="2026-10-02T16:00:{i:02d}Z"/>'
            "<Computer>DC01</Computer></System>"
            "<EventData>"
            '<Data Name="TargetUserName">admin</Data>'
            '<Data Name="IpAddress">203.0.113.9</Data>'
            "</EventData></Event>"
        )
    path = tmp_path / "sec.evtx.xml"
    path.write_text("<Events>\n" + "\n".join(events) + "\n</Events>\n")
    result = analyze_file(
        str(path),
        LogFilter().resolve(),
        AnalyzeOptions(auth_threshold=10),
    )
    assert result.parser == "winevent"
    bursts = [f for f in result.findings if "authentication-failure burst" in f.title]
    assert len(bursts) == 1
    assert "203.0.113.9" in bursts[0].title


def test_analyze_filters_compose(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(_auth_log_lines()) + "\n")
    filt = LogFilter(contains=("Accepted",), levels=("info",), limit=5).resolve()
    result = analyze_file(str(path), filt, AnalyzeOptions())
    assert result.events_matched == 1
    assert len(result.events) == 1
    assert "Accepted" in result.events[0]["message"]


def test_analyze_unknown_format_raises(tmp_path):
    path = tmp_path / "mystery.log"
    path.write_text("hello\nworld\nfoo bar baz\n")
    with pytest.raises(ValidationError):
        analyze_file(str(path), LogFilter().resolve(), AnalyzeOptions())


def test_analyze_explicit_format(tmp_path):
    path = tmp_path / "mystery.log"
    path.write_text("hello\nworld\n")
    result = analyze_file(
        str(path),
        LogFilter().resolve(),
        AnalyzeOptions(parser_name="keyvalue"),
    )
    assert result.parser == "keyvalue"
    assert result.warning_count == 2


def test_detect_bursts_unit():
    from datetime import datetime, timezone

    base = datetime(2026, 10, 2, 16, 0, 0, tzinfo=timezone.utc)
    moments = [base.replace(second=s) for s in range(60)]
    bursts = detect_bursts(moments, window_seconds=60, threshold=50)
    assert len(bursts) == 1
    assert bursts[0].count == 60
    assert detect_bursts(moments, window_seconds=60, threshold=61) == []
    assert detect_bursts([], 60, 1) == []


def test_analyze_events_in_memory():
    items = [
        LogEvent(
            message="Failed password for root from 203.0.113.7",
            timestamp="2026-10-02T16:00:01Z",
            parser="syslog",
            host="web1",
            severity="info",
            line_number=1,
        ),
        ParseWarning(line_number=2, reason="bad line"),
    ]
    result = analyze_events(items, LogFilter().resolve(), AnalyzeOptions())
    assert result.events_matched == 1
    assert result.warning_count == 1


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redact_text_ipv4_email():
    out = redact_text("from 203.0.113.7 by admin@example.com at 16:47:04")
    assert "203.0.113.7" not in out
    assert "xxx.xxx.xxx.xxx" in out
    assert "admin@example.com" not in out
    assert "[redacted-email]" in out
    assert "16:47:04" in out  # timestamps untouched


def test_redact_text_ipv6():
    out = redact_text("peer 2001:db8::1 connected")
    assert "2001:db8::1" not in out
    assert "[redacted-ipv6]" in out


def test_redact_value_nested():
    data = {"ip": "10.0.0.1", "nested": ["a@b.com", 42]}
    out = redact_value(data)
    assert out["ip"] == "xxx.xxx.xxx.xxx"
    assert out["nested"][0] == "[redacted-email]"
    assert out["nested"][1] == 42


def test_redact_cli_output_only(tmp_path, capsys):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(_auth_log_lines(3)) + "\n")
    before = path.read_text()
    code = cli_main.main(
        ["logs", "analyze", str(path), "--redact", "--format", "syslog"]
    )
    out, _ = capsys.readouterr()
    assert code == 0  # 3 failures < threshold 10 -> no findings
    assert "203.0.113.7" not in out
    assert "xxx.xxx.xxx.xxx" in out
    # Source file untouched.
    assert path.read_text() == before


# ---------------------------------------------------------------------------
# Streaming (bounded memory)
# ---------------------------------------------------------------------------


def test_parse_large_file_bounded_memory(tmp_path):
    path = tmp_path / "big.log"
    count = 200_000
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(
                f"Oct  2 16:00:01 web1 sshd[{i}]: "
                "Failed password for root from 203.0.113.7 port 50000 ssh2\n"
            )
    tracemalloc.start()
    parsed = 0
    for item in iter_parsed_file(str(path), SyslogParser()):
        assert isinstance(item, LogEvent)
        parsed += 1
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert parsed == count
    # 200k lines ~= 18MB on disk; streaming must stay far below that.
    assert peak < 5 * 1024 * 1024, f"peak {peak / 1024 / 1024:.1f}MB too high"


def test_analyze_large_file_streams(tmp_path):
    path = tmp_path / "big.log"
    count = 50_000
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(
                f"Oct  2 16:00:01 web1 sshd[{i}]: "
                "Failed password for root from 203.0.113.7 port 50000 ssh2\n"
            )
    tracemalloc.start()
    result = analyze_file(str(path), LogFilter(limit=100).resolve(), AnalyzeOptions())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert result.events_matched == count
    assert len(result.events) == 100  # display list bounded by --limit
    assert peak < 30 * 1024 * 1024, f"peak {peak / 1024 / 1024:.1f}MB too high"


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def _run_cli(argv):
    """Run the CLI, capturing stdout; returns (exit_code, stdout)."""
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main.main(argv)
    return code, buf.getvalue()


def test_cli_detect_and_analyze(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(_auth_log_lines()) + "\n")
    code, out = _run_cli(["logs", "detect", str(path)])
    assert code == 0
    assert "detected syslog" in out
    code, out = _run_cli(["logs", "analyze", str(path)])
    assert code == 1  # findings present
    assert "authentication-failure burst" in out


def test_cli_analyze_json_csv(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(_auth_log_lines(3)) + "\n")
    code, out = _run_cli(["logs", "analyze", str(path), "--json"])
    assert code == 0
    envelope = json.loads(out)
    assert envelope["command"] == "logs analyze"
    assert envelope["data"]["parser"] == "syslog"
    code, out = _run_cli(["logs", "analyze", str(path), "--csv"])
    assert code == 0
    assert out.splitlines()[0] == "line_number,timestamp,parser,host,severity,message"


def test_cli_analyze_missing_file():
    code, out = _run_cli(["logs", "analyze", "/nonexistent/file.log"])
    assert code == 2


def test_cli_detect_unknown_format(tmp_path):
    path = tmp_path / "mystery.log"
    path.write_text("hello\nworld\nfoo bar\n")
    code, out = _run_cli(["logs", "detect", str(path)])
    assert code == 0
    assert "unknown" in out


def test_logs_module_registered():
    info = get_registry().get("logs")
    assert info.version == "0.5.0"
    assert "logs analyze" in info.commands
    assert "logs detect" in info.commands
