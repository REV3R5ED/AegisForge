"""DNS record collection for a domain.

Queries A, AAAA, MX, NS, TXT, SOA and CNAME through
:mod:`aegisforge.domain.dns_client` and returns one structured mapping.
Every record type is attempted independently: a failing type produces a
warning entry, never an exception that aborts the rest.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import DNSError, DNSResponse

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")


@dataclass
class RecordCollection:
    """All collected record sets for one domain."""

    domain: str
    resolver: str | None
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _record_warnings(response: DNSResponse, domain: str, qtype: str) -> list[str]:
    notes = []
    for warning in response.warnings:
        notes.append(f"{qtype}: {warning}")
    return notes


def collect_records(
    domain: str,
    resolver: str | None = None,
    timeout: float = 5.0,
    record_types: tuple[str, ...] = RECORD_TYPES,
) -> RecordCollection:
    """Collect DNS records for *domain* across *record_types*."""
    collection = RecordCollection(domain=domain, resolver=resolver)
    for qtype in record_types:
        try:
            response = dns_client.query(
                domain, qtype, resolver=resolver, timeout=timeout
            )
        except (DNSError, ValueError) as exc:
            collection.warnings.append(f"{qtype}: query failed: {exc}")
            continue
        collection.records[qtype] = [answer.to_dict() for answer in response.answers]
        collection.warnings.extend(_record_warnings(response, domain, qtype))
        if qtype == "CNAME" and response.answers:
            # A CNAME alias answers for every other type too; note it once.
            target = response.answers[0].data.get("target")
            collection.warnings.append(f"{domain} is a CNAME alias for {target}")
    return collection
