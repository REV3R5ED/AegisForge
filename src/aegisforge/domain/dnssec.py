"""DNSSEC presence reporting (not validation).

Queries DNSKEY at the zone apex and DS at the parent side and reports
what signing evidence is *published*. AegisForge deliberately does not
claim chain validation — that requires a trust anchor and full
signature verification, which is out of scope. The report says what the
zone publishes and leaves the conclusion to the analyst.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.domain import dns_client
from aegisforge.domain.dns_client import DNSError


@dataclass
class DNSSECStatus:
    """Published DNSSEC evidence for a domain."""

    domain: str
    dnskey_records: list[dict[str, Any]] = field(default_factory=list)
    ds_records: list[dict[str, Any]] = field(default_factory=list)
    signed_evidence: str = "unknown"
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_dnssec(
    domain: str, resolver: str | None = None, timeout: float = 5.0
) -> DNSSECStatus:
    """Report DNSKEY/DS presence for *domain*."""
    status = DNSSECStatus(domain=domain)
    for qtype, bucket in (("DNSKEY", status.dnskey_records), ("DS", status.ds_records)):
        try:
            response = dns_client.query(
                domain, qtype, resolver=resolver, timeout=timeout
            )
        except DNSError as exc:
            status.warnings.append(f"{qtype} query failed: {exc}")
            continue
        bucket.extend(answer.to_dict() for answer in response.answers)
        status.warnings.extend(f"{qtype}: {w}" for w in response.warnings)
    has_dnskey = bool(status.dnskey_records)
    has_ds = bool(status.ds_records)
    if has_dnskey and has_ds:
        status.signed_evidence = "present"
        status.notes.append(
            "zone publishes DNSKEY and a DS record: signing evidence "
            "present (chain not validated by AegisForge)"
        )
    elif has_dnskey and not has_ds:
        status.signed_evidence = "partial"
        status.notes.append(
            "zone publishes DNSKEY but no DS record was found: signing "
            "evidence is incomplete from the parent side"
        )
    elif not has_dnskey and has_ds:
        status.signed_evidence = "partial"
        status.notes.append(
            "a DS record exists but no DNSKEY was published at the apex"
        )
    else:
        status.signed_evidence = "absent"
        status.notes.append(
            "no DNSKEY or DS records published: no DNSSEC signing "
            "evidence for this zone"
        )
    return status
