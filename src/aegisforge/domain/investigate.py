"""Consolidated domain investigation.

``investigate_domain`` runs every v0.3 collection step — DNS records,
reverse DNS, nameserver/MX analysis, DNSSEC presence, TLS inspection,
RDAP (with WHOIS fallback), ASN ownership and HTTP header/redirect
collection — and returns one combined report. Steps are independent:
a failing step records an error note, never aborts the rest.

Safety: everything here is passive directory lookups (DNS, RDAP,
WHOIS, HTTP). Unlike v0.2 port scanning there is no ``--allow-remote``
gate — nothing is sent to the target that its public services do not
already answer for any client.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisforge.core.findings import Finding
from aegisforge.domain import asn as asn_mod
from aegisforge.domain import dnssec as dnssec_mod
from aegisforge.domain import mx as mx_mod
from aegisforge.domain import nameservers as ns_mod
from aegisforge.domain import rdap as rdap_mod
from aegisforge.domain import records as records_mod
from aegisforge.domain import web as web_mod
from aegisforge.domain import whois as whois_mod
from aegisforge.network import dns as net_dns
from aegisforge.network import tls as tls_mod
from aegisforge.network.dns import DNSError as NetDNSError
from aegisforge.network.validation import ValidationError, validate_target

CERT_EXPIRY_SOON_DAYS = 30


@dataclass
class DomainOptions:
    """Knobs for a domain investigation."""

    resolver: str | None = None
    timeout: float = 5.0
    rdap: bool = True
    whois: bool = True
    web: bool = True
    tls: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    """Combined result of every v0.3 collection step for one domain."""

    domain: str
    dns: dict[str, Any] = field(default_factory=dict)
    reverse_dns: list[dict[str, Any]] = field(default_factory=list)
    nameservers: dict[str, Any] = field(default_factory=dict)
    mx: dict[str, Any] = field(default_factory=dict)
    dnssec: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    rdap: dict[str, Any] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    asn: list[dict[str, Any]] = field(default_factory=list)
    web: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_domain(domain: str) -> str:
    """Validate that *domain* is a hostname, not an IP literal."""
    cleaned = validate_target(domain)
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return cleaned.lower().rstrip(".")
    raise ValidationError(
        f"domain investigate expects a hostname, not an IP address: {cleaned!r} "
        "(use `network dns` for IP literals)"
    )


def _resolved_ips(report: InvestigationReport) -> list[str]:
    ips: list[str] = []
    for qtype in ("A", "AAAA"):
        for record in report.dns.get("records", {}).get(qtype, []):
            address = record.get("data", {}).get("address")
            if address and address not in ips:
                ips.append(address)
    return ips


def investigate_domain(
    domain: str, options: DomainOptions | None = None
) -> InvestigationReport:
    """Run the full v0.3 investigation for *domain*."""
    domain = validate_domain(domain)
    options = options or DomainOptions()
    report = InvestigationReport(domain=domain)

    # 1. DNS record collection.
    try:
        collection = records_mod.collect_records(
            domain, resolver=options.resolver, timeout=options.timeout
        )
        report.dns = collection.to_dict()
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"dns collection failed: {exc}")
        report.dns = {}

    # 2. Reverse DNS for every discovered address (existing network helper).
    for ip in _resolved_ips(report):
        try:
            reverse = net_dns.resolve_reverse(ip, timeout=options.timeout)
            report.reverse_dns.append(reverse.to_dict())
        except NetDNSError as exc:
            report.reverse_dns.append({"query": ip, "error": str(exc)})

    # 3. Nameserver analysis.
    try:
        report.nameservers = ns_mod.analyze_nameservers(
            domain, resolver=options.resolver, timeout=options.timeout
        ).to_dict()
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"nameserver analysis failed: {exc}")

    # 4. MX analysis.
    try:
        report.mx = mx_mod.analyze_mx(
            domain, resolver=options.resolver, timeout=options.timeout
        ).to_dict()
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"MX analysis failed: {exc}")

    # 5. DNSSEC presence.
    try:
        report.dnssec = dnssec_mod.check_dnssec(
            domain, resolver=options.resolver, timeout=options.timeout
        ).to_dict()
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"DNSSEC check failed: {exc}")

    # 6. TLS certificate inspection on 443 (reuses v0.2 network/tls.py).
    if options.tls:
        try:
            report.tls = tls_mod.inspect_tls(
                domain, port=443, timeout=options.timeout
            ).to_dict()
        except Exception as exc:  # pragma: no cover - defensive
            report.errors.append(f"TLS inspection failed: {exc}")
            report.tls = {}

    # 7. RDAP, with WHOIS fallback when RDAP yields nothing.
    rdap_result: rdap_mod.RDAPResult | None = None
    if options.rdap:
        try:
            rdap_result = rdap_mod.rdap_lookup(domain, timeout=options.timeout)
            report.rdap = rdap_result.to_dict()
        except Exception as exc:  # pragma: no cover - defensive
            report.errors.append(f"RDAP lookup failed: {exc}")
    if options.whois and (
        rdap_result is None or (rdap_result.error and not rdap_result.registrar)
    ):
        try:
            report.whois = whois_mod.whois_lookup(
                domain, timeout=options.timeout
            ).to_dict()
        except Exception as exc:  # pragma: no cover - defensive
            report.errors.append(f"WHOIS lookup failed: {exc}")

    # 8. ASN ownership for every resolved IP (Team Cymru DNS TXT).
    for ip in _resolved_ips(report):
        try:
            report.asn.append(
                asn_mod.asn_lookup(
                    ip, resolver=options.resolver, timeout=options.timeout
                ).to_dict()
            )
        except Exception as exc:  # pragma: no cover - defensive
            report.asn.append({"ip": ip, "error": str(exc)})

    # 9. HTTP/HTTPS headers and redirect chains.
    if options.web:
        for scheme in ("http", "https"):
            try:
                report.web[scheme] = web_mod.fetch_headers(
                    f"{scheme}://{domain}/", timeout=options.timeout
                ).to_dict()
            except Exception as exc:  # pragma: no cover - defensive
                report.web[scheme] = {"url": f"{scheme}://{domain}/", "error": str(exc)}

    return report


def analyze_findings(report: InvestigationReport) -> list[Finding]:
    """Derive analyst-facing findings from an investigation report.

    Every finding keeps the observed-vs-inferred discipline: ``evidence``
    lists what was observed, ``reason`` explains the inference.
    """
    findings: list[Finding] = []
    domain = report.domain

    # TLS findings.
    tls = report.tls
    if tls and not tls.get("error"):
        days = tls.get("days_until_expiry")
        if days is not None and days < 0:
            findings.append(
                Finding(
                    title=f"TLS certificate for {domain} has expired",
                    severity="high",
                    confidence=95,
                    reason=(
                        f"the certificate presented on port 443 expired "
                        f"{abs(days)} day(s) ago (not_after {tls.get('not_after')}); "
                        "clients will refuse the connection"
                    ),
                    evidence=[f"not_after={tls.get('not_after')}"],
                )
            )
        elif days is not None and days <= CERT_EXPIRY_SOON_DAYS:
            findings.append(
                Finding(
                    title=f"TLS certificate for {domain} expires in {days} day(s)",
                    severity="medium",
                    confidence=95,
                    reason=(
                        f"not_after is {tls.get('not_after')}; renewal is due "
                        "within 30 days"
                    ),
                    evidence=[f"not_after={tls.get('not_after')}"],
                )
            )
        if not tls.get("hostname_verified", True):
            findings.append(
                Finding(
                    title=f"TLS certificate does not match {domain}",
                    severity="high",
                    confidence=90,
                    reason=(
                        "the presented certificate's SAN/CN list does not "
                        f"cover {domain}; observed SANs: "
                        f"{', '.join(tls.get('san_dns_names', [])[:5]) or 'none'}"
                    ),
                    evidence=[f"san_dns_names={tls.get('san_dns_names', [])}"],
                )
            )

    # Mail findings.
    exchangers = report.mx.get("exchangers", []) if report.mx else []
    if report.mx and not exchangers and not report.mx.get("warnings"):
        findings.append(
            Finding(
                title=f"{domain} publishes no MX records",
                severity="info",
                confidence=90,
                reason=(
                    "the MX query returned no answers; the domain does not "
                    "advertise a mail exchanger (observation only — mail may "
                    "still be handled by A/AAAA fallback per RFC 5321)"
                ),
                evidence=["MX query: 0 answers"],
            )
        )
    for exchanger in exchangers:
        for issue in exchanger.get("issues", []):
            findings.append(
                Finding(
                    title=f"mail exchanger problem: {exchanger.get('exchange')}",
                    severity="low",
                    confidence=85,
                    reason=issue,
                    evidence=[f"MX preference={exchanger.get('preference')}"],
                )
            )

    # Nameserver findings.
    nameserver_list = (
        report.nameservers.get("nameservers", []) if report.nameservers else []
    )
    for nameserver in nameserver_list:
        for issue in nameserver.get("issues", []):
            findings.append(
                Finding(
                    title=f"nameserver delegation issue: {nameserver.get('hostname')}",
                    severity="medium",
                    confidence=80,
                    reason=issue,
                    evidence=[f"NS={nameserver.get('hostname')}"],
                )
            )

    # DNSSEC findings.
    if report.dnssec and report.dnssec.get("signed_evidence") == "absent":
        findings.append(
            Finding(
                title=f"{domain} publishes no DNSSEC signing evidence",
                severity="info",
                confidence=90,
                reason=(
                    "no DNSKEY or DS records were published for the zone; "
                    "DNS answers for this domain are not cryptographically "
                    "signed (observation only — absence of evidence, and "
                    "AegisForge does not validate chains)"
                ),
                evidence=["DNSKEY: 0 answers", "DS: 0 answers"],
            )
        )

    # Registration findings.
    for source, payload in (("RDAP", report.rdap), ("WHOIS", report.whois)):
        expiry = None
        if payload:
            expiry = payload.get("events", {}).get("expiration") or payload.get(
                "fields", {}
            ).get("expiry_date")
        if expiry:
            findings.append(
                Finding(
                    title=f"{domain} registration data observed ({source})",
                    severity="info",
                    confidence=70,
                    reason=(
                        f"{source} reports registrar "
                        f"{payload.get('registrar') or 'unknown'}; expiry field "
                        f"reads {expiry!r} (unparsed — verify before acting)"
                    ),
                    evidence=[f"{source} expiry field: {expiry}"],
                )
            )
            break

    return findings
