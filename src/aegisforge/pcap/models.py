"""Data models for offline PCAP analysis.

Every model carries a ``to_dict()`` so the CLI envelope, ``--json``
output and CSV rendering all share one contract. Malformed input never
raises out of the decoders: problems become :class:`PcapWarning`
records with a packet index and a reason.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.findings import SEVERITIES

#: Ports treated as "usual"; anything else is reported as unusual
#: (an observation, never an accusation).
COMMON_PORTS = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        69,
        80,
        110,
        119,
        123,
        135,
        137,
        138,
        139,
        143,
        161,
        162,
        389,
        443,
        445,
        465,
        514,
        515,
        587,
        636,
        993,
        995,
        1433,
        1521,
        1723,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        27017,
    }
)

#: Hard cap on HTTP-derived text kept per record (privacy: never full bodies).
MAX_HTTP_SNIPPET = 200


@dataclass
class PcapWarning:
    """Something odd about the capture or one packet; never fatal."""

    reason: str
    packet_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Packet:
    """One decoded packet (headers only; payloads are not retained)."""

    index: int
    timestamp: str  # UTC ISO-8601
    linktype: str
    protocols: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None  # "tcp" | "udp" | "icmp" | "icmpv6" | None
    length: int = 0  # on-wire captured length
    payload_length: int = 0  # transport payload bytes (not retained)
    tcp_flags: str = ""
    truncated: bool = False  # captured length < original length

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Flow:
    """One 5-tuple conversation aggregated over the capture."""

    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    packets: int = 0
    bytes: int = 0
    first_seen: str = ""
    last_seen: str = ""
    duration_s: float = 0.0
    tcp_flags: str = ""

    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.protocol, self.src_port, self.dst_port)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["duration_s"] = round(self.duration_s, 3)
        return d


@dataclass
class DnsActivity:
    """One observed DNS query (and its response, when seen)."""

    name: str
    qtype: str
    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HttpRecord:
    """One observed HTTP request/response line pair (truncated)."""

    timestamp: str
    src: str
    dst: str
    method: str = ""
    host: str = ""
    path: str = ""
    status: int | None = None
    user_agent: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TlsRecord:
    """One observed TLS ClientHello (metadata only)."""

    timestamp: str
    src: str
    dst: str
    sni: str = ""
    offered_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Indicator:
    """One deduplicated observed indicator.

    Every indicator is labeled "observed in capture" — observation,
    never a verdict about maliciousness (that is threat intel's job,
    v0.8).
    """

    itype: str  # "ip" | "domain" | "url"
    value: str
    first_seen: str = ""
    last_seen: str = ""
    sources: list[str] = field(default_factory=list)
    observation: str = "observed in capture"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    """One timestamped event for the core event model."""

    timestamp: str
    source: str
    kind: str
    summary: str
    severity: str = "info"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
