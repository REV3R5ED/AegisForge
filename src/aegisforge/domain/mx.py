"""MX analysis: which mail exchangers a domain publishes.

Lists MX records ordered by preference (lowest first, per RFC 5321)
and resolves each exchanger hostname to addresses. A domain with no MX
records is reported as an observation — it is not an error by itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import DNSError


@dataclass
class MailExchanger:
    """One MX target with its preference and resolved addresses."""

    exchange: str
    preference: int
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MXAnalysis:
    """Full MX picture for a domain."""

    domain: str
    exchangers: list[MailExchanger] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_mx(
    domain: str, resolver: str | None = None, timeout: float = 5.0
) -> MXAnalysis:
    """List MX records by preference and resolve each exchanger."""
    analysis = MXAnalysis(domain=domain)
    try:
        response = dns_client.query(domain, "MX", resolver=resolver, timeout=timeout)
    except DNSError as exc:
        analysis.warnings.append(f"MX query failed: {exc}")
        return analysis
    analysis.warnings.extend(f"MX: {w}" for w in response.warnings)
    for answer in response.answers:
        exchange = answer.data.get("exchange")
        if not exchange:
            continue
        exchanger = MailExchanger(
            exchange=exchange, preference=int(answer.data.get("preference", 0))
        )
        if exchange == ".":
            exchanger.issues.append(
                "null MX (RFC 7505): domain explicitly accepts no mail"
            )
            analysis.exchangers.append(exchanger)
            continue
        for qtype, bucket in (("A", exchanger.ipv4), ("AAAA", exchanger.ipv6)):
            try:
                host_response = dns_client.query(
                    exchange, qtype, resolver=resolver, timeout=timeout
                )
            except DNSError as exc:
                analysis.warnings.append(f"{exchange}/{qtype}: {exc}")
                continue
            for host_answer in host_response.answers:
                address = host_answer.data.get("address")
                if address and address not in bucket:
                    bucket.append(address)
        if not exchanger.ipv4 and not exchanger.ipv6:
            exchanger.issues.append(f"mail exchanger {exchange} has no A/AAAA records")
        analysis.exchangers.append(exchanger)
    analysis.exchangers.sort(key=lambda item: (item.preference, item.exchange))
    return analysis
