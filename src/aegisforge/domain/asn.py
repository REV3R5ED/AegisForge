"""ASN and IP-ownership enrichment via Team Cymru's DNS service.

Design choice: Team Cymru publishes ``<reversed-ip>.origin.asn.cymru.com``
TXT records of the form ``"ASN | prefix | CC | registry | allocated"``.
Querying them reuses our own DNS client — no extra protocol, no API
key, fully mockable. RDAP-for-IP was the alternative; the DNS route is
simpler, faster, and testable with the same byte vectors.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import DNSError

CYMRU_V4_ZONE = "origin.asn.cymru.com"
CYMRU_V6_ZONE = "origin6.asn.cymru.com"


@dataclass
class ASNInfo:
    """ASN ownership record for one IP address."""

    ip: str
    asn: str | None = None
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    allocated: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _cymru_name(ip: str) -> str:
    """Build the Team Cymru query name for *ip*."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"not an IP address: {ip!r}") from exc
    if isinstance(parsed, ipaddress.IPv4Address):
        reversed_octets = ".".join(reversed(ip.split(".")))
        return f"{reversed_octets}.{CYMRU_V4_ZONE}"
    nibbles = parsed.exploded.replace(":", "")[::-1]
    return f"{'.'.join(nibbles)}.{CYMRU_V6_ZONE}"


def asn_lookup(ip: str, resolver: str | None = None, timeout: float = 5.0) -> ASNInfo:
    """Look up ASN ownership for *ip* via Team Cymru DNS TXT."""
    info = ASNInfo(ip=ip)
    try:
        qname = _cymru_name(ip)
    except ValueError as exc:
        info.error = str(exc)
        return info
    try:
        response = dns_client.query(qname, "TXT", resolver=resolver, timeout=timeout)
    except DNSError as exc:
        info.error = f"Team Cymru query failed: {exc}"
        return info
    for answer in response.answers:
        text = answer.data.get("text", "")
        parts = [part.strip().strip('"') for part in text.split("|")]
        if len(parts) >= 5:
            info.asn = parts[0] or None
            info.prefix = parts[1] or None
            info.country = parts[2] or None
            info.registry = parts[3] or None
            info.allocated = parts[4] or None
            return info
    info.error = "no usable Team Cymru TXT record returned"
    return info
