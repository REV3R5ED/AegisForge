"""Aggregation and detection over a decoded packet stream.

Every public function makes a single streaming pass over the capture —
packets are decoded, aggregated and dropped one at a time, so memory
stays bounded regardless of capture size. Malformed packets become
:class:`PcapWarning` records, never exceptions.

Findings follow the observed-vs-inferred discipline: ``OBSERVED``
states exactly what the capture shows, ``INFERRED`` states the
hypothesis and names what would confirm or refute it.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from aegisforge.core.findings import Finding
from aegisforge.pcap import decoders
from aegisforge.pcap.decoders import Decoded, DecodeError
from aegisforge.pcap.dns_extract import is_dns_payload, parse_dns_message
from aegisforge.pcap.http_extract import extract_http
from aegisforge.pcap.models import (
    COMMON_PORTS,
    DnsActivity,
    Flow,
    HttpRecord,
    Indicator,
    Packet,
    PcapWarning,
    TimelineEvent,
    TlsRecord,
)
from aegisforge.pcap.reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    iter_packets,
    linktype_name,
    read_global_header,
)
from aegisforge.pcap.tls_extract import extract_tls

#: Packet decode batching is unnecessary — one packet at a time is the
#: whole point — but DNS/HTTP/TLS extraction only runs on relevant ports
#: to avoid wasting cycles on bulk traffic.
DNS_PORT = 53
HTTP_PORT = 80
TLS_PORT = 443


@dataclass
class AnalyzeOptions:
    """Tunable knobs for pcap analysis (config file may override)."""

    burst_window: int = 60  # seconds
    burst_threshold: int = 50  # new flows from one source per window
    unusual_port_packets: int = 10  # min packets on an unusual port to flag
    top: int = 10  # rows kept for top-N lists


def _parse_ts(value: str) -> datetime:
    """Parse the reader's UTC ISO-8601 (handles the trailing Z on 3.10)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _walk(path: str, warnings: list[PcapWarning]) -> Iterator[tuple[Packet, Decoded]]:
    """Yield ``(Packet, Decoded)`` for every decodable packet.

    Unsupported linktypes are recorded once as a warning and every
    packet on them is skipped; undecodable packets become warnings.
    """
    header, offset = read_global_header(path)
    link_name = linktype_name(header.linktype)
    if header.linktype not in (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL):
        warnings.append(
            PcapWarning(
                reason=(
                    f"unsupported linktype {header.linktype} "
                    f"({link_name}); packets skipped"
                )
            )
        )
        return
    for index, timestamp, data, truncated in iter_packets(
        path, header, offset, warnings
    ):
        try:
            decoded = decoders.decode_frame(data, header.linktype)
        except DecodeError as exc:
            warnings.append(
                PcapWarning(reason=f"packet decode failed: {exc}", packet_index=index)
            )
            continue
        packet = Packet(
            index=index,
            timestamp=timestamp,
            linktype=link_name,
            protocols=decoded.protocols,
            src_ip=decoded.src_ip,
            dst_ip=decoded.dst_ip,
            src_port=decoded.src_port,
            dst_port=decoded.dst_port,
            protocol=decoded.protocol,
            length=len(data),
            payload_length=len(decoded.payload),
            tcp_flags=decoded.tcp_flags,
            truncated=truncated,
        )
        yield packet, decoded


def _is_unusual(port: int | None) -> bool:
    return port is not None and port not in COMMON_PORTS


def _burst_findings(
    flow_starts: list[tuple[str, str]], options: AnalyzeOptions
) -> list[Finding]:
    """Flag sources opening many new flows inside one window."""
    # flow_starts: (src_ip, timestamp_iso)
    windows: dict[tuple[str, int], int] = defaultdict(int)
    for src, ts in flow_starts:
        try:
            epoch = int(_parse_ts(ts).timestamp())
        except ValueError:
            continue
        windows[(src, epoch // options.burst_window)] += 1
    findings: list[Finding] = []
    for (src, window), count in sorted(windows.items()):
        if count >= options.burst_threshold:
            window_start = datetime.fromtimestamp(
                window * options.burst_window, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            findings.append(
                Finding(
                    title="High connection frequency",
                    severity="medium",
                    confidence=65,
                    reason=(
                        f"OBSERVED: {count} new flows from {src} within "
                        f"{options.burst_window}s (window starting "
                        f"{window_start}). INFERRED: may indicate scanning "
                        "or aggressive reconnection — correlate with "
                        "firewall/auth logs before treating as hostile."
                    ),
                    evidence=[f"{count} new flows from {src}"],
                    data={
                        "src_ip": src,
                        "window_start": window_start,
                        "window_s": options.burst_window,
                        "new_flows": count,
                    },
                )
            )
    return findings


def _unusual_port_findings(
    port_counts: Counter, options: AnalyzeOptions
) -> list[Finding]:
    findings: list[Finding] = []
    for (proto, port), count in port_counts.most_common():
        if count < options.unusual_port_packets:
            break
        findings.append(
            Finding(
                title="Unusual port activity",
                severity="medium",
                confidence=60,
                reason=(
                    f"OBSERVED: {count} packets on {proto}/{port}, which is "
                    "not in the common-ports set. INFERRED: may indicate a "
                    "non-standard service or tunneling — investigate the "
                    "endpoints before drawing conclusions."
                ),
                evidence=[f"{count} packets on {proto}/{port}"],
                data={"protocol": proto, "port": port, "packets": count},
            )
        )
    return findings


@dataclass
class SummaryResult:
    packet_count: int = 0
    total_bytes: int = 0
    time_first: str | None = None
    time_last: str | None = None
    protocol_histogram: list[list[Any]] = field(default_factory=list)
    top_talkers_packets: list[list[Any]] = field(default_factory=list)
    top_talkers_bytes: list[list[Any]] = field(default_factory=list)
    top_ports: list[list[Any]] = field(default_factory=list)
    unusual_ports: list[dict[str, Any]] = field(default_factory=list)
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


def summarize(path: str, options: AnalyzeOptions) -> SummaryResult:
    """Full single-pass aggregation: stats, talkers, ports, findings."""
    result = SummaryResult()
    warnings: list[PcapWarning] = []
    proto_hist: Counter = Counter()
    talker_packets: Counter = Counter()
    talker_bytes: Counter = Counter()
    port_counts: Counter = Counter()
    unusual: Counter = Counter()
    flow_starts: list[tuple[str, str]] = []
    seen_flows: set[tuple] = set()

    for packet, _ in _walk(path, warnings):
        result.packet_count += 1
        result.total_bytes += packet.length
        if result.time_first is None:
            result.time_first = packet.timestamp
        result.time_last = packet.timestamp
        for proto in packet.protocols:
            proto_hist[proto] += 1
        if packet.src_ip:
            talker_packets[packet.src_ip] += 1
            talker_bytes[packet.src_ip] += packet.length
        if packet.dst_ip:
            talker_packets[packet.dst_ip] += 1
        for port, transport_proto in (
            (packet.src_port, packet.protocol),
            (packet.dst_port, packet.protocol),
        ):
            if port is not None and transport_proto in ("tcp", "udp"):
                port_counts[port] += 1
                if _is_unusual(port):
                    unusual[(transport_proto, port)] += 1
        # Flow-start tracking for burst detection.
        if packet.protocol in ("tcp", "udp") and packet.src_ip and packet.dst_ip:
            key = (
                packet.src_ip,
                packet.dst_ip,
                packet.protocol,
                packet.src_port,
                packet.dst_port,
            )
            if key not in seen_flows:
                seen_flows.add(key)
                flow_starts.append((packet.src_ip, packet.timestamp))

    result.protocol_histogram = [
        [proto, count] for proto, count in proto_hist.most_common()
    ]
    result.top_talkers_packets = [
        [ip, count] for ip, count in talker_packets.most_common(options.top)
    ]
    result.top_talkers_bytes = [
        [ip, count] for ip, count in talker_bytes.most_common(options.top)
    ]
    result.top_ports = [
        [port, count] for port, count in port_counts.most_common(options.top)
    ]
    result.unusual_ports = [
        {"protocol": proto, "port": port, "packets": count}
        for (proto, port), count in unusual.most_common(options.top)
    ]
    result.findings.extend(_unusual_port_findings(unusual, options))
    result.findings.extend(_burst_findings(flow_starts, options))
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class ConversationsResult:
    flows: list[Flow] = field(default_factory=list)
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flows": [f.to_dict() for f in self.flows],
            "flow_count": len(self.flows),
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def conversations(path: str, options: AnalyzeOptions) -> ConversationsResult:
    """Aggregate 5-tuple flows with packet/byte counts and TCP flags."""
    result = ConversationsResult()
    warnings: list[PcapWarning] = []
    flows: dict[tuple, Flow] = {}
    for packet, _ in _walk(path, warnings):
        if packet.protocol not in ("tcp", "udp"):
            continue
        if not packet.src_ip or not packet.dst_ip:
            continue
        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.protocol or "unknown",
            packet.src_port,
            packet.dst_port,
        )
        flow = flows.get(key)
        if flow is None:
            flow = Flow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol=packet.protocol or "unknown",
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                first_seen=packet.timestamp,
            )
            flows[key] = flow
        flow.packets += 1
        flow.bytes += packet.length
        flow.last_seen = packet.timestamp
        for flag in packet.tcp_flags:
            if flag not in flow.tcp_flags:
                flow.tcp_flags += flag
    ordered = sorted(flows.values(), key=lambda f: (-f.packets, f.first_seen))[
        : options.top
    ]
    for flow in ordered:
        try:
            delta = (
                _parse_ts(flow.last_seen) - _parse_ts(flow.first_seen)
            ).total_seconds()
            flow.duration_s = max(0.0, delta)
        except ValueError:
            flow.duration_s = 0.0
    result.flows = ordered
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class DnsResult:
    queries: list[DnsActivity] = field(default_factory=list)
    malformed_count: int = 0
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "queries": [q.to_dict() for q in self.queries],
            "query_count": len(self.queries),
            "malformed_count": self.malformed_count,
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def dns_activity(path: str, options: AnalyzeOptions) -> DnsResult:
    """Extract DNS queries/responses from UDP/53 payloads."""
    result = DnsResult()
    warnings: list[PcapWarning] = []
    activities: dict[tuple[str, str], DnsActivity] = {}
    for packet, decoded in _walk(path, warnings):
        if decoded.protocol != "udp":
            continue
        if packet.src_port != DNS_PORT and packet.dst_port != DNS_PORT:
            continue
        payload = decoded.payload
        if not is_dns_payload(payload):
            result.malformed_count += 1
            continue
        msg = parse_dns_message(payload)
        if msg["malformed"]:
            result.malformed_count += 1
            continue
        for question in msg["questions"]:
            key = (question["name"], question["qtype"])
            activity = activities.get(key)
            if activity is None:
                activity = DnsActivity(
                    name=question["name"],
                    qtype=question["qtype"],
                    first_seen=packet.timestamp,
                )
                activities[key] = activity
            activity.last_seen = packet.timestamp
            if msg["is_response"]:
                activity.responses += 1
                if msg["rcode"] == 3:
                    activity.nxdomain += 1
            else:
                activity.queries += 1
    result.queries = sorted(
        activities.values(), key=lambda a: (-(a.queries + a.responses), a.name)
    )[: options.top]
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class HttpResult:
    records: list[HttpRecord] = field(default_factory=list)
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "record_count": len(self.records),
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def http_metadata(path: str, options: AnalyzeOptions) -> HttpResult:
    """Extract HTTP request/response metadata from TCP/80 payloads."""
    result = HttpResult()
    warnings: list[PcapWarning] = []
    for packet, decoded in _walk(path, warnings):
        if decoded.protocol != "tcp":
            continue
        if packet.src_port != HTTP_PORT and packet.dst_port != HTTP_PORT:
            continue
        if not decoded.payload:
            continue
        if packet.src_ip is None or packet.dst_ip is None:
            continue
        records = extract_http(
            decoded.payload, packet.timestamp, packet.src_ip, packet.dst_ip
        )
        result.records.extend(records)
    result.records = result.records[: options.top]
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class TlsResult:
    records: list[TlsRecord] = field(default_factory=list)
    failed_count: int = 0
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "record_count": len(self.records),
            "failed_count": self.failed_count,
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def tls_metadata(path: str, options: AnalyzeOptions) -> TlsResult:
    """Extract TLS ClientHello SNI/version from TCP/443 payloads."""
    result = TlsResult()
    warnings: list[PcapWarning] = []
    for packet, decoded in _walk(path, warnings):
        if decoded.protocol != "tcp":
            continue
        if packet.src_port != TLS_PORT and packet.dst_port != TLS_PORT:
            continue
        if not decoded.payload or len(decoded.payload) < 5:
            continue
        if packet.src_ip is None or packet.dst_ip is None:
            continue
        records = extract_tls(
            decoded.payload, packet.timestamp, packet.src_ip, packet.dst_ip
        )
        if records:
            result.records.extend(records)
        else:
            result.failed_count += 1
    result.records = result.records[: options.top]
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class IndicatorsResult:
    indicators: list[Indicator] = field(default_factory=list)
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicators": [i.to_dict() for i in self.indicators],
            "indicator_count": len(self.indicators),
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def _note_indicator(
    seen: dict[tuple[str, str], Indicator],
    itype: str,
    value: str,
    timestamp: str,
    source: str,
) -> None:
    value = value.strip().rstrip(".")
    if not value:
        return
    key = (itype, value)
    indicator = seen.get(key)
    if indicator is None:
        indicator = Indicator(itype=itype, value=value, first_seen=timestamp)
        seen[key] = indicator
    indicator.last_seen = timestamp
    if source not in indicator.sources:
        indicator.sources.append(source)


def extract_indicators(path: str, options: AnalyzeOptions) -> IndicatorsResult:
    """Deduped observed indicators: IPs, domains (DNS/Host/SNI), URLs."""
    result = IndicatorsResult()
    warnings: list[PcapWarning] = []
    seen: dict[tuple[str, str], Indicator] = {}
    for packet, decoded in _walk(path, warnings):
        ts = packet.timestamp
        if packet.src_ip:
            _note_indicator(seen, "ip", packet.src_ip, ts, "packet")
        if packet.dst_ip:
            _note_indicator(seen, "ip", packet.dst_ip, ts, "packet")
        payload = decoded.payload
        if decoded.protocol == "udp" and (
            packet.src_port == DNS_PORT or packet.dst_port == DNS_PORT
        ):
            if not is_dns_payload(payload):
                continue
            msg = parse_dns_message(payload)
            if msg["malformed"]:
                continue
            for question in msg["questions"]:
                _note_indicator(seen, "domain", question["name"], ts, "dns-query")
            for answer in msg["answers"]:
                _note_indicator(seen, "domain", answer["name"], ts, "dns-answer")
        if decoded.protocol == "tcp" and (
            packet.src_port == HTTP_PORT or packet.dst_port == HTTP_PORT
        ):
            for http_rec in extract_http(
                payload, ts, packet.src_ip or "", packet.dst_ip or ""
            ):
                if http_rec.host:
                    _note_indicator(seen, "domain", http_rec.host, ts, "http-host")
                    if http_rec.path and http_rec.path != "/":
                        _note_indicator(
                            seen,
                            "url",
                            f"{http_rec.host}{http_rec.path}"[:200],
                            ts,
                            "http-request",
                        )
        if decoded.protocol == "tcp" and (
            packet.src_port == TLS_PORT or packet.dst_port == TLS_PORT
        ):
            for tls_rec in extract_tls(
                payload, ts, packet.src_ip or "", packet.dst_ip or ""
            ):
                if tls_rec.sni:
                    _note_indicator(seen, "domain", tls_rec.sni, ts, "tls-sni")
    result.indicators = sorted(seen.values(), key=lambda i: (i.itype, i.value))
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


@dataclass
class PcapTimelineResult:
    events: list[TimelineEvent] = field(default_factory=list)
    warning_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "event_count": len(self.events),
            "warning_count": self.warning_count,
            "warnings": self.warnings,
        }


def timeline(path: str, options: AnalyzeOptions) -> PcapTimelineResult:
    """Timestamped events (flow starts, DNS queries) for the event model."""
    result = PcapTimelineResult()
    warnings: list[PcapWarning] = []
    seen_flows: set[tuple] = set()
    for packet, decoded in _walk(path, warnings):
        if packet.protocol in ("tcp", "udp") and packet.src_ip and packet.dst_ip:
            key = (
                packet.src_ip,
                packet.dst_ip,
                packet.protocol,
                packet.src_port,
                packet.dst_port,
            )
            if key not in seen_flows:
                seen_flows.add(key)
                port = packet.dst_port
                result.events.append(
                    TimelineEvent(
                        timestamp=packet.timestamp,
                        source="pcap",
                        kind="flow-start",
                        summary=(
                            f"new {packet.protocol} flow "
                            f"{packet.src_ip}:{packet.src_port} -> "
                            f"{packet.dst_ip}:{port}"
                        ),
                    )
                )
        if (
            decoded.protocol == "udp"
            and (packet.src_port == DNS_PORT or packet.dst_port == DNS_PORT)
            and is_dns_payload(decoded.payload)
        ):
            msg = parse_dns_message(decoded.payload)
            if msg["malformed"]:
                continue
            for question in msg["questions"]:
                if not msg["is_response"]:
                    result.events.append(
                        TimelineEvent(
                            timestamp=packet.timestamp,
                            source="pcap",
                            kind="dns-query",
                            summary=(
                                f"DNS query {question['name']} "
                                f"({question['qtype']}) from {packet.src_ip}"
                            ),
                        )
                    )
    result.events.sort(key=lambda e: e.timestamp)
    result.warnings = [w.to_dict() for w in warnings]
    result.warning_count = len(warnings)
    return result


__all__ = [
    "AnalyzeOptions",
    "ConversationsResult",
    "DnsResult",
    "HttpResult",
    "IndicatorsResult",
    "PcapTimelineResult",
    "SummaryResult",
    "TlsResult",
    "conversations",
    "dns_activity",
    "extract_indicators",
    "http_metadata",
    "summarize",
    "timeline",
    "tls_metadata",
]
