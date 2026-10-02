"""Tests for domain investigation orchestration and findings (all I/O mocked)."""

import pytest

from aegisforge.domain.investigate import (
    DomainOptions,
    InvestigationReport,
    analyze_findings,
    investigate_domain,
    validate_domain,
)
from aegisforge.network.validation import ValidationError


@pytest.fixture()
def everything_mocked(monkeypatch):
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

    monkeypatch.setattr(
        records_mod,
        "collect_records",
        lambda domain, **k: records_mod.RecordCollection(
            domain=domain,
            resolver=None,
            records={
                "A": [
                    {
                        "name": domain,
                        "rtype": "A",
                        "ttl": 300,
                        "data": {"address": "93.184.216.34"},
                    }
                ],
                "MX": [],
            },
            warnings=[],
        ),
    )
    monkeypatch.setattr(
        net_dns,
        "resolve_reverse",
        lambda ip, **k: net_dns.DNSResult(
            query=ip,
            addresses=[{"ip": ip, "family": "IPv4"}],
            reverse_name="example.com",
        ),
    )
    monkeypatch.setattr(
        ns_mod,
        "analyze_nameservers",
        lambda domain, **k: ns_mod.NameserverAnalysis(domain=domain),
    )
    monkeypatch.setattr(
        mx_mod, "analyze_mx", lambda domain, **k: mx_mod.MXAnalysis(domain=domain)
    )
    monkeypatch.setattr(
        dnssec_mod,
        "check_dnssec",
        lambda domain, **k: dnssec_mod.DNSSECStatus(
            domain=domain, signed_evidence="absent"
        ),
    )
    monkeypatch.setattr(
        tls_mod,
        "inspect_tls",
        lambda host, **k: tls_mod.TLSInfo(
            host=host,
            port=443,
            days_until_expiry=10,
            hostname_verified=True,
            not_after="2026-11-01T00:00:00Z",
        ),
    )
    monkeypatch.setattr(
        rdap_mod,
        "rdap_lookup",
        lambda domain, **k: rdap_mod.RDAPResult(domain=domain, registrar="Example"),
    )
    monkeypatch.setattr(
        whois_mod,
        "whois_lookup",
        lambda domain, **k: (_ for _ in ()).throw(
            AssertionError("WHOIS must not run when RDAP succeeds")
        ),
    )
    monkeypatch.setattr(
        asn_mod,
        "asn_lookup",
        lambda ip, **k: asn_mod.ASNInfo(ip=ip, asn="15169"),
    )
    monkeypatch.setattr(
        web_mod,
        "fetch_headers",
        lambda url, **k: web_mod.WebResult(url=url, status_code=200),
    )


def test_investigate_runs_all_sections(everything_mocked):
    report = investigate_domain("example.com", DomainOptions())
    assert report.domain == "example.com"
    assert report.dns["records"]["A"][0]["data"]["address"] == "93.184.216.34"
    assert report.reverse_dns[0]["reverse_name"] == "example.com"
    assert report.tls["days_until_expiry"] == 10
    assert report.rdap["registrar"] == "Example"
    assert report.whois == {}  # RDAP succeeded -> no WHOIS fallback
    assert report.asn[0]["asn"] == "15169"
    assert report.web["http"]["status_code"] == 200
    assert report.errors == []


def test_investigate_whois_fallback_when_rdap_fails(monkeypatch):
    from aegisforge.domain import rdap as rdap_mod
    from aegisforge.domain import records as records_mod
    from aegisforge.domain import whois as whois_mod

    monkeypatch.setattr(
        records_mod,
        "collect_records",
        lambda domain, **k: records_mod.RecordCollection(domain=domain),
    )
    monkeypatch.setattr(
        rdap_mod,
        "rdap_lookup",
        lambda domain, **k: rdap_mod.RDAPResult(domain=domain, error="offline"),
    )
    monkeypatch.setattr(
        whois_mod,
        "whois_lookup",
        lambda domain, **k: whois_mod.WhoisResult(
            query=domain,
            server="whois.iana.org",
            fields={"registrar": "Fallback Registrar"},
        ),
    )
    report = investigate_domain(
        "example.com",
        DomainOptions(tls=False, web=False, rdap=True, whois=True),
    )
    assert report.whois["fields"]["registrar"] == "Fallback Registrar"


def test_investigate_skips_disabled_sections(everything_mocked, monkeypatch):
    from aegisforge.domain import web as web_mod

    called = []
    monkeypatch.setattr(
        web_mod, "fetch_headers", lambda url, **k: called.append(url) or None
    )
    report = investigate_domain(
        "example.com", DomainOptions(web=False, tls=False, rdap=False, whois=False)
    )
    assert called == []
    assert report.web == {}
    assert report.tls == {}
    assert report.rdap == {}
    assert report.whois == {}


def test_validate_domain_rejects_ip():
    with pytest.raises(ValidationError, match="not an IP address"):
        validate_domain("93.184.216.34")


def test_validate_domain_normalizes():
    assert validate_domain("Example.COM.") == "example.com"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _report(**overrides):
    base = InvestigationReport(domain="example.com")
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_finding_cert_expired():
    report = _report(
        tls={
            "error": None,
            "days_until_expiry": -5,
            "not_after": "2026-09-01T00:00:00Z",
            "hostname_verified": True,
            "san_dns_names": ["example.com"],
        }
    )
    findings = analyze_findings(report)
    assert any(f.severity == "high" and "expired" in f.title for f in findings)


def test_finding_cert_expiring_soon():
    report = _report(
        tls={
            "error": None,
            "days_until_expiry": 10,
            "not_after": "2026-10-12T00:00:00Z",
            "hostname_verified": True,
            "san_dns_names": ["example.com"],
        }
    )
    findings = analyze_findings(report)
    assert any(f.severity == "medium" and "expires in 10" in f.title for f in findings)


def test_finding_cert_hostname_mismatch():
    report = _report(
        tls={
            "error": None,
            "days_until_expiry": 300,
            "not_after": "2027-01-01T00:00:00Z",
            "hostname_verified": False,
            "san_dns_names": ["other.com"],
        }
    )
    findings = analyze_findings(report)
    assert any("does not match" in f.title for f in findings)


def test_finding_no_mx():
    report = _report(mx={"exchangers": [], "warnings": []})
    findings = analyze_findings(report)
    assert any("no MX records" in f.title for f in findings)


def test_finding_lame_nameserver():
    report = _report(
        nameservers={
            "nameservers": [
                {"hostname": "dead.example.com", "issues": ["no A/AAAA records"]}
            ]
        }
    )
    findings = analyze_findings(report)
    assert any("delegation issue" in f.title for f in findings)


def test_finding_dnssec_absent():
    report = _report(dnssec={"signed_evidence": "absent"})
    findings = analyze_findings(report)
    assert any("no DNSSEC" in f.title for f in findings)


def test_finding_rdap_expiry_observed():
    report = _report(
        rdap={"registrar": "Example", "events": {"expiration": "2030-01-01T00:00:00Z"}}
    )
    findings = analyze_findings(report)
    match = [f for f in findings if "RDAP" in f.title]
    assert match and "unparsed" in match[0].reason


def test_no_findings_for_clean_report():
    report = _report(
        tls={
            "error": None,
            "days_until_expiry": 300,
            "not_after": "2027-01-01T00:00:00Z",
            "hostname_verified": True,
            "san_dns_names": ["example.com"],
        },
        mx={"exchangers": [{"exchange": "mx.example.com", "issues": []}]},
        nameservers={"nameservers": []},
        dnssec={"signed_evidence": "present"},
    )
    assert analyze_findings(report) == []


def test_tls_error_produces_no_tls_findings():
    report = _report(tls={"error": "connection refused"})
    findings = analyze_findings(report)
    assert not any("TLS" in f.title for f in findings)
