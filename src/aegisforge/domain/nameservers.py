"""Nameserver analysis: who is authoritative, and are they reachable?

Lists the NS records for a domain, resolves each nameserver hostname
to A/AAAA addresses, and flags delegation problems — a nameserver with
no address records cannot serve the zone (lame delegation).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import DNSError


@dataclass
class NameserverInfo:
    """One authoritative nameserver and its resolved addresses."""

    hostname: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    glue_ttl: int | None = None
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NameserverAnalysis:
    """Full nameserver picture for a domain."""

    domain: str
    nameservers: list[NameserverInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _resolve_host(
    hostname: str, resolver: str | None, timeout: float
) -> tuple[list[str], list[str], list[str]]:
    """Resolve a nameserver hostname to (ipv4, ipv6, warnings)."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    warnings: list[str] = []
    for qtype, bucket in (("A", ipv4), ("AAAA", ipv6)):
        try:
            response = dns_client.query(
                hostname, qtype, resolver=resolver, timeout=timeout
            )
        except DNSError as exc:
            warnings.append(f"{hostname}/{qtype}: {exc}")
            continue
        for answer in response.answers:
            address = answer.data.get("address")
            if address and address not in bucket:
                bucket.append(address)
        warnings.extend(f"{hostname}/{qtype}: {w}" for w in response.warnings)
    return ipv4, ipv6, warnings


def analyze_nameservers(
    domain: str, resolver: str | None = None, timeout: float = 5.0
) -> NameserverAnalysis:
    """List NS records and resolve each nameserver to addresses."""
    analysis = NameserverAnalysis(domain=domain)
    try:
        response = dns_client.query(domain, "NS", resolver=resolver, timeout=timeout)
    except DNSError as exc:
        analysis.warnings.append(f"NS query failed: {exc}")
        return analysis
    analysis.warnings.extend(f"NS: {w}" for w in response.warnings)
    for answer in response.answers:
        hostname = answer.data.get("nameserver")
        if not hostname:
            continue
        info = NameserverInfo(hostname=hostname, glue_ttl=answer.ttl)
        info.ipv4, info.ipv6, resolve_warnings = _resolve_host(
            hostname, resolver, timeout
        )
        analysis.warnings.extend(resolve_warnings)
        if not info.ipv4 and not info.ipv6:
            info.issues.append(
                f"nameserver {hostname} has no A/AAAA records: "
                "cannot be reached for this zone (possible lame delegation)"
            )
        analysis.nameservers.append(info)
    if not analysis.nameservers and response.ok:
        analysis.warnings.append(f"{domain} publishes no NS records")
    return analysis
