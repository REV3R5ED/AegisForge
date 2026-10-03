"""Log analysis: timeline, histograms, top talkers, bursts, findings.

Analysis runs in a single streaming pass over the parsed events:
aggregates (histograms, top talkers, burst windows) are computed over
the *full* stream while only a bounded number of events is retained
for display. Error context lines are collected with a second,
line-targeted pass over the file.

Findings keep the observed-vs-inferred discipline: a burst of 404s
is *observed*; calling it an attack is *inferred* and is labeled as
such in the finding reason.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from aegisforge.core.findings import Finding
from aegisforge.logs import detect as detect_mod
from aegisforge.logs.filters import LogFilter
from aegisforge.logs.models import PARSER_UNKNOWN, LogEvent, ParseWarning
from aegisforge.logs.parsers import get_parser, iter_parsed_file
from aegisforge.network.validation import ValidationError

_AUTH_FAIL_RE = re.compile(
    r"(?i)(failed\s+password|authentication\s+failure|failed\s+logon|"
    r"logon\s+failure|failed\s+login|invalid\s+user)"
)
_EXCEPTION_RE = re.compile(r"(?i)(exception|traceback|panic:|fatal error)")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

#: Windows "failed logon" event id.
WINEVENT_AUTH_FAIL_ID = "4625"

#: Cap on retained display events / error entries (bounded memory).
DEFAULT_MAX_ERRORS = 50
#: Cap on warning samples kept in the envelope.
MAX_WARNING_SAMPLES = 25


@dataclass
class AnalyzeOptions:
    """Knobs for :func:`analyze_file`."""

    parser_name: str = "auto"
    burst_window: int = 60
    burst_threshold: int = 50
    auth_window: int = 300
    auth_threshold: int = 10
    http_5xx_window: int = 300
    http_5xx_threshold: int = 20
    exception_cluster_threshold: int = 5
    context_lines: int = 3
    max_errors: int = DEFAULT_MAX_ERRORS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Burst:
    window_start: str
    window_end: str
    count: int
    key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorEntry:
    event: dict[str, Any]
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    path: str
    parser: str
    detection: dict[str, Any] = field(default_factory=dict)
    total_lines: int = 0
    events_matched: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)
    warning_count: int = 0
    time_first: str | None = None
    time_last: str | None = None
    severity_histogram: dict[str, int] = field(default_factory=dict)
    status_histogram: dict[str, int] = field(default_factory=dict)
    top_ips: list[list[Any]] = field(default_factory=list)
    top_hosts: list[list[Any]] = field(default_factory=list)
    hourly: list[list[Any]] = field(default_factory=list)
    bursts: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)  # capped display list
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


def _parse_ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def detect_bursts(
    moments: list[datetime],
    window_seconds: int,
    threshold: int,
    key: str | None = None,
) -> list[Burst]:
    """Fixed-window burst detection over sorted *moments*."""
    bursts: list[Burst] = []
    if not moments or window_seconds <= 0:
        return bursts
    ordered = sorted(moments)
    start = ordered[0]
    buckets: Counter[int] = Counter()
    for moment in ordered:
        buckets[int((moment - start).total_seconds()) // window_seconds] += 1
    for bucket in sorted(buckets):
        count = buckets[bucket]
        if count >= threshold:
            win_start = start + timedelta(seconds=bucket * window_seconds)
            bursts.append(
                Burst(
                    window_start=win_start.isoformat().replace("+00:00", "Z"),
                    window_end=(win_start + timedelta(seconds=window_seconds))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    count=count,
                    key=key,
                )
            )
    return bursts


def _event_ips(event: LogEvent) -> list[str]:
    found: list[str] = []
    for field_value in event.fields.values():
        if isinstance(field_value, str):
            found.extend(_IPV4_RE.findall(field_value))
    found.extend(_IPV4_RE.findall(event.message))
    # IPv6: only tokens with 3+ colons or hex letters (never timestamps).
    for token in _IPV6_RE.findall(event.message):
        if token.count(":") >= 3 or re.search(r"[a-fA-F]", token):
            found.append(token)
    return found


def _is_auth_failure(event: LogEvent) -> bool:
    if event.fields.get("event_id") == WINEVENT_AUTH_FAIL_ID:
        return True
    return bool(_AUTH_FAIL_RE.search(event.message))


def _auth_key(event: LogEvent) -> str:
    for key in ("ipaddress", "ip_address", "src_ip", "source_ip"):
        value = event.fields.get(key)
        if value:
            return str(value)
    ips = _event_ips(event)
    if ips:
        return ips[0]
    return event.host or "(unknown)"


def _exception_signature(event: LogEvent) -> str | None:
    if not _EXCEPTION_RE.search(event.message):
        return None
    match = re.search(
        r"(?i)([\w.]*?(?:Exception|Error|Panic)\w*)\s*[:\-]", event.message
    )
    if match:
        return match.group(1).lower()
    return event.message.splitlines()[0][:80].lower()


def _hourly_buckets(moments: list[datetime]) -> list[list[Any]]:
    if not moments:
        return []
    ordered = sorted(moments)
    span_hours = (ordered[-1] - ordered[0]).total_seconds() / 3600
    # Widen the bucket for long ranges so the table stays bounded.
    bucket_seconds = 3600 if span_hours <= 500 else 86400
    buckets: Counter[str] = Counter()
    for moment in ordered:
        epoch = int(moment.timestamp()) // bucket_seconds * bucket_seconds
        label = (
            datetime.fromtimestamp(epoch, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        buckets[label] += 1
    return [[label, buckets[label]] for label in sorted(buckets)]


@dataclass
class _Aggregate:
    """Intermediate single-pass aggregation state."""

    result: AnalysisResult
    severity_hist: Counter[str] = field(default_factory=Counter)
    status_hist: Counter[str] = field(default_factory=Counter)
    ip_hist: Counter[str] = field(default_factory=Counter)
    host_hist: Counter[str] = field(default_factory=Counter)
    moments: list[datetime] = field(default_factory=list)
    auth_times: dict[str, list[datetime]] = field(default_factory=dict)
    http5xx_times: list[datetime] = field(default_factory=list)
    exception_groups: dict[str, list[LogEvent]] = field(default_factory=dict)
    error_events: list[LogEvent] = field(default_factory=list)


def _aggregate(
    items: Iterable[LogEvent | ParseWarning],
    filt: LogFilter,
    options: AnalyzeOptions,
    result: AnalysisResult,
) -> _Aggregate:
    """Single streaming pass: aggregates over the full stream, keeps a
    bounded display list (``filt.limit``) and bounded error entries."""
    agg = _Aggregate(result=result)
    limit = filt.limit
    for item in items:
        if isinstance(item, ParseWarning):
            result.warning_count += 1
            if len(result.warnings) < MAX_WARNING_SAMPLES:
                result.warnings.append(item.to_dict())
            continue
        result.total_lines += 1
        if not filt.matches(item):
            continue
        result.events_matched += 1
        agg.severity_hist[item.severity] += 1
        if item.host:
            agg.host_hist[item.host] += 1
        for ip in _event_ips(item):
            agg.ip_hist[ip] += 1
        status = item.fields.get("status")
        if isinstance(status, int):
            agg.status_hist[str(status)] += 1
            if status >= 500 and item.timestamp:
                agg.http5xx_times.append(_parse_ts(item.timestamp))
        if item.timestamp:
            agg.moments.append(_parse_ts(item.timestamp))
        if _is_auth_failure(item) and item.timestamp:
            agg.auth_times.setdefault(_auth_key(item), []).append(
                _parse_ts(item.timestamp)
            )
        signature = _exception_signature(item)
        if signature:
            agg.exception_groups.setdefault(signature, []).append(item)
        if item.severity in ("high", "critical"):
            if len(agg.error_events) < options.max_errors:
                agg.error_events.append(item)
        if limit is None or len(result.events) < limit:
            result.events.append(item.to_dict())
    return agg


def _finalize(agg: _Aggregate, options: AnalyzeOptions) -> None:
    """Fill histograms, bursts and findings from aggregation state."""
    result = agg.result
    if agg.moments:
        result.time_first = min(agg.moments).isoformat().replace("+00:00", "Z")
        result.time_last = max(agg.moments).isoformat().replace("+00:00", "Z")
    result.severity_histogram = dict(sorted(agg.severity_hist.items()))
    result.status_histogram = dict(sorted(agg.status_hist.items()))
    result.top_ips = [[ip, c] for ip, c in agg.ip_hist.most_common(10)]
    result.top_hosts = [[h, c] for h, c in agg.host_hist.most_common(10)]
    result.hourly = _hourly_buckets(agg.moments)
    for burst in detect_bursts(
        agg.moments, options.burst_window, options.burst_threshold
    ):
        result.bursts.append(burst.to_dict())
    for event in agg.error_events:
        result.errors.append(ErrorEntry(event=event.to_dict()).to_dict())
    _build_findings(
        result, agg.auth_times, agg.http5xx_times, agg.exception_groups, options
    )


def analyze_events(
    items: list[LogEvent | ParseWarning],
    filt: LogFilter,
    options: AnalyzeOptions,
    path: str = "",
    detection: dict[str, Any] | None = None,
    parser_name: str = PARSER_UNKNOWN,
    raw_lines: dict[int, str] | None = None,
) -> AnalysisResult:
    """Analyze an in-memory item list (single pass; used by tests)."""
    result = AnalysisResult(
        path=path,
        parser=parser_name,
        detection=detection or {},
    )
    agg = _aggregate(iter(items), filt, options, result)
    _finalize(agg, options)
    # Context fallback: raw text of the matched events themselves.
    line_text: dict[int, str] = dict(raw_lines or {})
    if not line_text:
        for item in items:
            if isinstance(item, LogEvent) and filt.matches(item):
                line_text[item.line_number] = item.raw or item.message
    _attach_context(result, line_text, options)
    return result


def _attach_context(
    result: AnalysisResult,
    line_text: dict[int, str],
    options: AnalyzeOptions,
) -> None:
    """Fill context_before/after for each recorded error entry."""
    if options.context_lines <= 0 or not result.errors:
        return
    window = options.context_lines
    for entry in result.errors:
        lineno = entry["event"]["line_number"]
        before = [
            line_text[n] for n in range(lineno - window, lineno) if n in line_text
        ]
        after = [
            line_text[n]
            for n in range(lineno + 1, lineno + window + 1)
            if n in line_text
        ]
        entry["context_before"] = before[-window:]
        entry["context_after"] = after[:window]


def _build_findings(
    result: AnalysisResult,
    auth_times: dict[str, list[datetime]],
    http5xx_times: list[datetime],
    exception_groups: dict[str, list[LogEvent]],
    options: AnalyzeOptions,
) -> None:
    for key, times in sorted(auth_times.items()):
        for burst in detect_bursts(times, options.auth_window, options.auth_threshold):
            severity = "high" if burst.count >= 50 else "medium"
            result.findings.append(
                Finding(
                    title=f"authentication-failure burst from {key}",
                    severity=severity,
                    confidence=70,
                    reason=(
                        f"OBSERVED: {burst.count} failed authentication attempts "
                        f"from {key} within {options.auth_window}s "
                        f"(window starting {burst.window_start}). INFERRED: "
                        "pattern is consistent with password-guessing "
                        "(brute-force) activity — corroborate before concluding."
                    ),
                    evidence=[
                        f"{burst.count} failures in window {burst.window_start}",
                        f"source key: {key}",
                    ],
                )
            )
    for burst in detect_bursts(
        http5xx_times, options.http_5xx_window, options.http_5xx_threshold
    ):
        result.findings.append(
            Finding(
                title="HTTP 5xx error spike",
                severity="medium",
                confidence=75,
                reason=(
                    f"OBSERVED: {burst.count} HTTP 5xx responses within "
                    f"{options.http_5xx_window}s (window starting "
                    f"{burst.window_start}). INFERRED: may indicate backend "
                    "failure or overload — check application logs."
                ),
                evidence=[f"{burst.count} 5xx in window {burst.window_start}"],
            )
        )
    for signature, events in sorted(
        exception_groups.items(), key=lambda kv: len(kv[1]), reverse=True
    ):
        if len(events) < options.exception_cluster_threshold:
            continue
        first = events[0]
        result.findings.append(
            Finding(
                title=f"exception cluster: {signature} ({len(events)} occurrences)",
                severity="medium",
                confidence=70,
                reason=(
                    f"OBSERVED: {len(events)} log events share the exception "
                    f"signature {signature!r} "
                    f"(first at line {first.line_number}). INFERRED: may "
                    "indicate a recurring defect — review the stack traces."
                ),
                evidence=[
                    f"signature: {signature}",
                    f"occurrences: {len(events)}",
                    f"first line: {first.line_number}",
                ],
            )
        )


def analyze_file(path: str, filt: LogFilter, options: AnalyzeOptions) -> AnalysisResult:
    """Stream-analyze the log file at *path* (two bounded passes max)."""
    filt.resolve()
    if options.parser_name == "auto":
        detection = detect_mod.detect_file(path).to_dict()
        parser_name = detection["parser"]
        if parser_name == PARSER_UNKNOWN:
            raise ValidationError(
                "could not detect log format (confidence below "
                f"{detect_mod.MIN_CONFIDENCE}); pass --format explicitly"
            )
    else:
        parser_name = options.parser_name
        detection = {
            "parser": parser_name,
            "confidence": 1.0,
            "scores": {},
            "lines_sampled": 0,
        }
    parser = get_parser(parser_name)
    result = AnalysisResult(
        path=path,
        parser=parser_name,
        detection=detection,
    )
    # Streaming: the parsed generator is consumed once; aggregates are
    # computed over the full stream while retained events stay bounded.
    agg = _aggregate(iter_parsed_file(path, parser), filt, options, result)
    _finalize(agg, options)

    # Second pass: raw context lines around errors (bounded).
    raw_lines: dict[int, str] = {}
    if options.context_lines > 0 and result.errors:
        wanted: set[int] = set()
        for entry in result.errors:
            lineno = entry["event"]["line_number"]
            wanted.update(
                range(
                    lineno - options.context_lines, lineno + options.context_lines + 1
                )
            )
        with open(path, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if number in wanted:
                    raw_lines[number] = line.rstrip("\n").rstrip("\r")
    _attach_context(result, raw_lines, options)
    return result
