"""Streaming log parsers (stdlib only).

Each parser reads line-by-line and yields :class:`LogEvent` or
:class:`ParseWarning` — a whole file is never loaded into memory.
Malformed lines become warnings with line numbers, never exceptions.

Formats: syslog (RFC 3164 + RFC 5424), Apache/Nginx combined and
common access logs, JSON lines, Windows Event Log XML exports
(as-exported XML fragments, not EVTX binaries), and generic
``key=value`` lines.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET

from aegisforge.logs.models import (
    PARSER_APACHE,
    PARSER_JSON,
    PARSER_KEYVALUE,
    PARSER_SYSLOG,
    PARSER_WINEVENT,
    LogEvent,
    ParseWarning,
)

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_SYSLOG_SEVERITY = {
    0: "critical",  # emerg
    1: "critical",  # alert
    2: "high",  # crit
    3: "high",  # err
    4: "medium",  # warning
    5: "low",  # notice
    6: "info",  # info
    7: "info",  # debug
}

_LEVEL_NAMES = {
    "trace": "info",
    "debug": "info",
    "info": "info",
    "notice": "low",
    "warn": "medium",
    "warning": "medium",
    "error": "high",
    "err": "high",
    "fatal": "critical",
    "crit": "critical",
    "critical": "critical",
    "alert": "critical",
    "emerg": "critical",
    "emergency": "critical",
}

_WINDOWS_LEVELS = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "info",
    "5": "info",
    "0": "info",
}


def to_utc_iso(moment: datetime) -> str:
    """Format a datetime as UTC ISO-8601 (``...Z``)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_timestamp(value: Any) -> str | None:
    """Best-effort parse of ISO-8601 / epoch timestamps to UTC ISO-8601."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return to_utc_iso(datetime.fromtimestamp(value, tz=timezone.utc))
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    candidate = text.replace("Z", "+00:00") if text.endswith(("Z", "z")) else text
    # Python < 3.11 fromisoformat only accepts 3 or 6 fractional-second digits;
    # Windows emits 7 (.NET ticks). Truncate to microseconds (the most Python
    # can represent) so parsing behaves identically on 3.10–3.13.
    candidate = _LONG_FRACTION_RE.sub(lambda m: "." + m.group(1)[:6], candidate)
    try:
        return to_utc_iso(datetime.fromisoformat(candidate))
    except ValueError:
        return None


def normalize_level(value: Any) -> str:
    """Map a free-form level name / syslog number to a normalized severity."""
    if value is None:
        return "info"
    text = str(value).strip().lower()
    if text in _LEVEL_NAMES:
        return _LEVEL_NAMES[text]
    if text.isdigit():
        return _SYSLOG_SEVERITY.get(int(text) & 0x7, "info")
    return "info"


class BaseParser:
    """One streaming log format parser."""

    name: str = "unknown"

    def matches(self, line: str) -> bool:
        """True when *line* looks like this format (for auto-detection)."""
        raise NotImplementedError

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        """Parse one line. None = blank line, skip silently."""
        raise NotImplementedError

    def parse_lines(self, lines: Iterable[str]) -> Iterator[LogEvent | ParseWarning]:
        for number, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n").rstrip("\r")
            if not stripped.strip():
                continue
            item = self.parse_line(stripped, number)
            if item is not None:
                yield item


# ---------------------------------------------------------------------------
# Syslog (RFC 3164 + RFC 5424)
# ---------------------------------------------------------------------------

_RFC3164 = re.compile(
    r"^(?:<(\d{1,3})>)?"
    r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
    r"(\S+)\s+([^:]{1,64}):\s*(.*)$"
)
_RFC5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$"
)


class SyslogParser(BaseParser):
    name = PARSER_SYSLOG

    def matches(self, line: str) -> bool:
        return bool(_RFC3164.match(line) or _RFC5424.match(line))

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        m5424 = _RFC5424.match(line)
        if m5424:
            return self._parse_5424(m5424, line, line_number)
        m3164 = _RFC3164.match(line)
        if m3164:
            return self._parse_3164(m3164, line, line_number)
        return ParseWarning(line_number, "not a recognized syslog line", line)

    def _severity_from_pri(self, pri: str | None) -> str:
        if pri is None:
            return "info"
        return _SYSLOG_SEVERITY.get(int(pri) & 0x7, "info")

    def _parse_3164(
        self, match: re.Match[str], line: str, line_number: int
    ) -> LogEvent:
        pri, mon, day, hh, mm, ss, host, tag, message = match.groups()
        month = _MONTHS[mon.lower()]
        year = datetime.now(timezone.utc).year
        moment = datetime(
            year, month, int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc
        )
        process: str | None = None
        pid: str | None = None
        proc_match = re.match(r"^([^\[]+)\[(\d+)\]$", tag.strip())
        if proc_match:
            process, pid = proc_match.groups()
        else:
            process = tag.strip()
        fields: dict[str, Any] = {"process": process}
        if pid:
            fields["pid"] = pid
        if pri is not None:
            fields["facility"] = int(pri) >> 3
        return LogEvent(
            message=message,
            timestamp=to_utc_iso(moment),
            parser=self.name,
            host=host,
            severity=self._severity_from_pri(pri),
            fields=fields,
            raw=line,
            line_number=line_number,
        )

    def _parse_5424(
        self, match: re.Match[str], line: str, line_number: int
    ) -> LogEvent | ParseWarning:
        pri, _version, ts, host, app, procid, msgid, rest = match.groups()
        timestamp = parse_iso_timestamp(ts) if ts != "-" else None
        message = rest
        fields: dict[str, Any] = {
            "app": None if app == "-" else app,
            "procid": None if procid == "-" else procid,
            "msgid": None if msgid == "-" else msgid,
            "facility": int(pri) >> 3,
        }
        if rest.startswith("["):
            end = self._structured_end(rest)
            if end is None:
                return ParseWarning(
                    line_number, "unterminated RFC 5424 structured data", line
                )
            fields["structured_data"] = rest[: end + 1]
            message = rest[end + 1 :].lstrip()
        return LogEvent(
            message=message,
            timestamp=timestamp,
            parser=self.name,
            host=None if host == "-" else host,
            severity=self._severity_from_pri(pri),
            fields=fields,
            raw=line,
            line_number=line_number,
        )

    @staticmethod
    def _structured_end(text: str) -> int | None:
        depth = 0
        escaped = False
        for i, ch in enumerate(text):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return i
        return None


# ---------------------------------------------------------------------------
# Apache / Nginx access logs (combined + common)
# ---------------------------------------------------------------------------

_APACHE = re.compile(
    r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)'
    r'(?: "([^"]*)" "([^"]*)")?\s*$'
)
_APACHE_TIME = "%d/%b/%Y:%H:%M:%S %z"

# Fractional seconds with more than 6 digits (e.g. Windows 7-digit ticks).
_LONG_FRACTION_RE = re.compile(r"\.(\d{7,})")


def _apache_severity(status: int) -> str:
    if status >= 500:
        return "high"
    if status >= 400:
        return "medium"
    if status >= 300:
        return "low"
    return "info"


class ApacheParser(BaseParser):
    name = PARSER_APACHE

    def matches(self, line: str) -> bool:
        return bool(_APACHE.match(line))

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        match = _APACHE.match(line)
        if not match:
            return ParseWarning(
                line_number, "not an Apache/Nginx access log line", line
            )
        remote, _logname, user, ts, request, status_s, size_s, referer, agent = (
            match.groups()
        )
        try:
            moment = datetime.strptime(ts, _APACHE_TIME)
            timestamp = to_utc_iso(moment)
        except ValueError:
            timestamp = None
        status = int(status_s)
        method: str | None = None
        path: str | None = None
        parts = request.split()
        if len(parts) == 3:
            method, path, _proto = parts
        elif len(parts) == 2:
            method, path = parts
        fields: dict[str, Any] = {
            "remote": remote,
            "user": None if user == "-" else user,
            "method": method,
            "path": path,
            "request": request,
            "status": status,
            "bytes": None if size_s == "-" else int(size_s),
            "referer": None if referer in (None, "-") else referer,
            "user_agent": agent,
        }
        message = f"{method or '?'} {path or request} -> {status}"
        return LogEvent(
            message=message,
            timestamp=timestamp,
            parser=self.name,
            host=remote,
            severity=_apache_severity(status),
            fields=fields,
            raw=line,
            line_number=line_number,
        )


# ---------------------------------------------------------------------------
# JSON lines
# ---------------------------------------------------------------------------

_TS_KEYS = ("timestamp", "@timestamp", "ts", "time", "datetime", "event_time")
_MSG_KEYS = ("message", "msg", "log", "event", "text")
_LEVEL_KEYS = ("level", "severity", "loglevel", "log_level")
_HOST_KEYS = ("host", "hostname", "computer", "server", "src_host")


class JsonLinesParser(BaseParser):
    name = PARSER_JSON

    def matches(self, line: str) -> bool:
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            return False
        try:
            return isinstance(json.loads(stripped), dict)
        except (json.JSONDecodeError, ValueError):
            return False

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            return ParseWarning(line_number, f"invalid JSON: {exc.msg}", line)
        if not isinstance(obj, dict):
            return ParseWarning(line_number, "JSON line is not an object", line)
        data: dict[str, Any] = dict(obj)
        timestamp = None
        for key in _TS_KEYS:
            if key in data:
                timestamp = parse_iso_timestamp(data.pop(key))
                break
        message = ""
        for key in _MSG_KEYS:
            if key in data and data[key] is not None:
                message = str(data.pop(key))
                break
        severity = "info"
        for key in _LEVEL_KEYS:
            if key in data:
                severity = normalize_level(data.pop(key))
                break
        host = None
        for key in _HOST_KEYS:
            if key in data and data[key] is not None:
                host = str(data.pop(key))
                break
        if not message:
            message = json.dumps(data, sort_keys=True)[:500]
        return LogEvent(
            message=message,
            timestamp=timestamp,
            parser=self.name,
            host=host,
            severity=severity,
            fields=data,
            raw=line,
            line_number=line_number,
        )


# ---------------------------------------------------------------------------
# Windows Event Log XML export (as-exported XML, not EVTX binary)
# ---------------------------------------------------------------------------

_EVENT_START = re.compile(r"<Event[\s>]")
_EVENT_END = "</Event>"
# Harmless wrapper/declaration lines that are silently skipped.
_XML_WRAPPER = re.compile(r"^\s*(<\?xml\b|</?Events\s*>)\s*$")
# Tag markers identifying Windows Event Log XML (used for detection —
# inner lines of a multi-line <Event> must score too, not just the
# <Event> line itself).
_WINEVENT_MARKERS = (
    "<Event",
    "</Event",
    "<System>",
    "</System>",
    "<EventID>",
    "<Level>",
    "<TimeCreated",
    "<Computer>",
    "<Provider",
    "<Channel>",
    "<EventData>",
    "</EventData>",
    "<Data Name=",
    "<RenderingInfo>",
    "<Message>",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_text(parent: ET.Element, local_name: str) -> str | None:
    for child in parent:
        if _local(child.tag) == local_name and child.text:
            return child.text.strip()
    return None


class WindowsXmlParser(BaseParser):
    """Parses ``<Event>…</Event>`` fragments from an exported XML log.

    The file is read in a streaming fashion: lines accumulate only
    until the closing ``</Event>`` tag, then the fragment is parsed.
    """

    name = PARSER_WINEVENT

    def matches(self, line: str) -> bool:
        return any(marker in line for marker in _WINEVENT_MARKERS)

    def parse_lines(self, lines: Iterable[str]) -> Iterator[LogEvent | ParseWarning]:
        buffer: list[str] = []
        in_event = False
        start_number = 0
        for number, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n").rstrip("\r")
            if not in_event:
                if _EVENT_START.search(stripped):
                    in_event = True
                    start_number = number
                    buffer = [stripped]
                    if _EVENT_END in stripped:
                        yield self._parse_fragment(buffer, start_number)
                        in_event = False
                        buffer = []
                elif not stripped.strip() or _XML_WRAPPER.match(stripped):
                    continue
                else:
                    yield ParseWarning(number, "line outside any <Event>", stripped)
                continue
            buffer.append(stripped)
            if _EVENT_END in stripped:
                yield self._parse_fragment(buffer, start_number)
                in_event = False
                buffer = []
        if in_event:
            yield ParseWarning(
                start_number, "unterminated <Event> at end of file", buffer[0][:200]
            )

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        # Single-line use (detection/tests): wrap the line as a fragment.
        return self._parse_fragment([line], line_number)

    def _parse_fragment(
        self, fragment: list[str], line_number: int
    ) -> LogEvent | ParseWarning:
        text = "\n".join(fragment)
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            return ParseWarning(line_number, f"invalid event XML: {exc}", text[:200])
        if _local(root.tag) != "Event":
            return ParseWarning(
                line_number, "XML fragment is not an <Event>", text[:200]
            )
        system = event_data = rendering = None
        for child in root:
            local = _local(child.tag)
            if local == "System":
                system = child
            elif local == "EventData":
                event_data = child
            elif local == "RenderingInfo":
                rendering = child
        event_id = _find_text(system, "EventID") if system is not None else None
        level = _find_text(system, "Level") if system is not None else None
        computer = _find_text(system, "Computer") if system is not None else None
        timestamp = None
        provider = None
        channel = None
        if system is not None:
            for child in system:
                local = _local(child.tag)
                if local == "TimeCreated":
                    timestamp = parse_iso_timestamp(child.attrib.get("SystemTime"))
                elif local == "Provider":
                    provider = child.attrib.get("Name")
                elif local == "Channel" and child.text:
                    channel = child.text.strip()
        data_fields: dict[str, Any] = {}
        if event_data is not None:
            for data in event_data:
                if _local(data.tag) == "Data":
                    name = data.attrib.get("Name", "data").lower()
                    data_fields[name] = (data.text or "").strip()
        message = None
        if rendering is not None:
            message = _find_text(rendering, "Message")
        if not message:
            bits = [f"{k}={v}" for k, v in data_fields.items() if v][:6]
            message = f"EventID {event_id or '?'}" + (
                f": {', '.join(bits)}" if bits else ""
            )
        fields: dict[str, Any] = {"event_id": event_id, **data_fields}
        if provider:
            fields["provider"] = provider
        if channel:
            fields["channel"] = channel
        return LogEvent(
            message=message,
            timestamp=timestamp,
            parser=self.name,
            host=computer,
            severity=_WINDOWS_LEVELS.get((level or "").strip(), "info"),
            fields=fields,
            raw=text[:2000],
            line_number=line_number,
        )


# ---------------------------------------------------------------------------
# Generic key=value
# ---------------------------------------------------------------------------

_KV_PAIR = re.compile(r'([A-Za-z_][\w.\-]*)=(?:"([^"]*)"|(\S*))')


class KeyValueParser(BaseParser):
    name = PARSER_KEYVALUE

    def matches(self, line: str) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith(("{", "<", "[")):
            return False
        pairs = _KV_PAIR.findall(stripped)
        if not pairs:
            return False
        # At least one pair must start at the beginning or after whitespace.
        first = _KV_PAIR.search(stripped)
        return first is not None and (
            first.start() == 0 or stripped[: first.start()].strip() == ""
        )

    def parse_line(self, line: str, line_number: int) -> LogEvent | ParseWarning | None:
        pairs = _KV_PAIR.findall(line)
        if not pairs:
            return ParseWarning(line_number, "no key=value pairs found", line)
        fields: dict[str, Any] = {}
        for key, quoted, bare in pairs:
            # Prefer the quoted value when present, else the bare token.
            fields[key.lower()] = quoted if quoted else bare
        timestamp = None
        for key in ("ts", "timestamp", "time", "datetime"):
            if key in fields:
                timestamp = parse_iso_timestamp(fields.pop(key))
                break
        message = ""
        for key in ("msg", "message", "log"):
            if key in fields and fields[key]:
                message = str(fields.pop(key))
                break
        if not message:
            message = line.strip()[:500]
        severity = "info"
        for key in ("level", "severity"):
            if key in fields:
                severity = normalize_level(fields.pop(key))
                break
        host = None
        for key in ("host", "hostname"):
            if key in fields and fields[key]:
                host = str(fields.pop(key))
                break
        return LogEvent(
            message=message,
            timestamp=timestamp,
            parser=self.name,
            host=host,
            severity=severity,
            fields=fields,
            raw=line,
            line_number=line_number,
        )


PARSER_CLASSES: tuple[type[BaseParser], ...] = (
    SyslogParser,
    ApacheParser,
    JsonLinesParser,
    WindowsXmlParser,
    KeyValueParser,
)


def get_parser(name: str) -> BaseParser:
    """Return a parser instance by name (raises KeyError for unknown)."""
    for cls in PARSER_CLASSES:
        if cls.name == name:
            return cls()
    raise KeyError(
        f"unknown log parser {name!r}; expected one of "
        f"{[c.name for c in PARSER_CLASSES]}"
    )


def iter_parsed_file(
    path: str, parser: BaseParser
) -> Iterator[LogEvent | ParseWarning]:
    """Stream-parse *path* with *parser* (text mode, undecodable bytes replaced)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from parser.parse_lines(fh)
