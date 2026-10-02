"""Tests for domain sections: records, nameservers, MX, DNSSEC (DNS mocked)."""

import pytest

from aegisforge.domain import asn as asn_mod
from aegisforge.domain import dnssec as dnssec_mod
from aegisforge.domain import mx as mx_mod
from aegisforge.domain import nameservers as ns_mod
from aegisforge.domain import records as records_mod
from aegisforge.domain.dns_client import DNSResponse


def _response(qname, qtype, answers=(), warnings=(), rcode=0):
    from aegisforge.domain.dns_client import DNSRecord

    records = [
        DNSRecord(name=qname, rtype=qtype, ttl=300, data=data) for data in answers
    ]
    return DNSResponse(
        qname=qname,
        qtype=qtype,
        rcode=rcode,
        answers=records,
        warnings=list(warnings),
    )


@pytest.fixture()
def fake_dns(monkeypatch):
    table = {}

    def fake_query(name, qtype, resolver=None, timeout=5.0):
        key = (name.rstrip("."), qtype.upper())
        if key not in table:
            raise AssertionError(f"unexpected DNS query: {key}")
        value = table[key]
        if isinstance(value, Exception):
            raise value
        return value

    from aegisforge.domain import dns_client

    monkeypatch.setattr(dns_client, "query", fake_query)
    return table


def test_collect_records_all_types(fake_dns):
    domain = "example.com"
    fake_dns[(domain, "A")] = _response(domain, "A", [{"address": "93.184.216.34"}])
    fake_dns[(domain, "AAAA")] = _response(domain, "AAAA", [])
    fake_dns[(domain, "MX")] = _response(
        domain, "MX", [{"preference": 10, "exchange": "mail.example.com"}]
    )
    fake_dns[(domain, "NS")] = _response(
        domain, "NS", [{"nameserver": "ns1.example.com"}]
    )
    fake_dns[(domain, "TXT")] = _response(
        domain, "TXT", [{"text": "v=spf1 -all", "strings": ["v=spf1 -all"]}]
    )
    fake_dns[(domain, "SOA")] = _response(
        domain, "SOA", [{"mname": "ns1.example.com", "serial": 1}]
    )
    fake_dns[(domain, "CNAME")] = _response(domain, "CNAME", [])
    collection = records_mod.collect_records(domain)
    assert collection.records["A"][0]["data"]["address"] == "93.184.216.34"
    assert collection.records["MX"][0]["data"]["exchange"] == "mail.example.com"
    assert collection.records["AAAA"] == []
    assert collection.warnings == []


def test_collect_records_failure_is_warning(fake_dns):
    from aegisforge.domain.dns_client import DNSError

    fake_dns[("example.com", "A")] = DNSError("boom")
    for qtype in ("AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        fake_dns[("example.com", qtype)] = _response("example.com", qtype, [])
    collection = records_mod.collect_records("example.com")
    assert any(w.startswith("A:") and "boom" in w for w in collection.warnings)


def test_nameserver_analysis_resolves(fake_dns):
    fake_dns[("example.com", "NS")] = _response(
        "example.com", "NS", [{"nameserver": "ns1.example.com"}]
    )
    fake_dns[("ns1.example.com", "A")] = _response(
        "ns1.example.com", "A", [{"address": "192.0.2.1"}]
    )
    fake_dns[("ns1.example.com", "AAAA")] = _response("ns1.example.com", "AAAA", [])
    analysis = ns_mod.analyze_nameservers("example.com")
    assert len(analysis.nameservers) == 1
    info = analysis.nameservers[0]
    assert info.hostname == "ns1.example.com"
    assert info.ipv4 == ["192.0.2.1"]
    assert info.issues == []


def test_nameserver_without_addresses_flagged(fake_dns):
    fake_dns[("example.com", "NS")] = _response(
        "example.com", "NS", [{"nameserver": "dead.example.com"}]
    )
    fake_dns[("dead.example.com", "A")] = _response("dead.example.com", "A", [])
    fake_dns[("dead.example.com", "AAAA")] = _response("dead.example.com", "AAAA", [])
    analysis = ns_mod.analyze_nameservers("example.com")
    assert len(analysis.nameservers[0].issues) == 1
    assert "lame delegation" in analysis.nameservers[0].issues[0]


def test_mx_sorted_by_preference(fake_dns):
    fake_dns[("example.com", "MX")] = _response(
        "example.com",
        "MX",
        [
            {"preference": 20, "exchange": "mx2.example.com"},
            {"preference": 10, "exchange": "mx1.example.com"},
        ],
    )
    for host in ("mx1.example.com", "mx2.example.com"):
        fake_dns[(host, "A")] = _response(host, "A", [{"address": "192.0.2.10"}])
        fake_dns[(host, "AAAA")] = _response(host, "AAAA", [])
    analysis = mx_mod.analyze_mx("example.com")
    assert [e.exchange for e in analysis.exchangers] == [
        "mx1.example.com",
        "mx2.example.com",
    ]


def test_mx_null_mx_noted(fake_dns):
    fake_dns[("example.com", "MX")] = _response(
        "example.com", "MX", [{"preference": 0, "exchange": "."}]
    )
    analysis = mx_mod.analyze_mx("example.com")
    assert "null MX" in analysis.exchangers[0].issues[0]


def test_mx_no_records_empty(fake_dns):
    fake_dns[("example.com", "MX")] = _response("example.com", "MX", [])
    analysis = mx_mod.analyze_mx("example.com")
    assert analysis.exchangers == []


def test_dnssec_present(fake_dns):
    fake_dns[("example.com", "DNSKEY")] = _response(
        "example.com", "DNSKEY", [{"flags": 257, "key_tag": 1234}]
    )
    fake_dns[("example.com", "DS")] = _response(
        "example.com", "DS", [{"key_tag": 1234}]
    )
    status = dnssec_mod.check_dnssec("example.com")
    assert status.signed_evidence == "present"
    assert "not validated" in " ".join(status.notes)


def test_dnssec_absent(fake_dns):
    fake_dns[("example.com", "DNSKEY")] = _response("example.com", "DNSKEY", [])
    fake_dns[("example.com", "DS")] = _response("example.com", "DS", [])
    status = dnssec_mod.check_dnssec("example.com")
    assert status.signed_evidence == "absent"


def test_dnssec_partial(fake_dns):
    fake_dns[("example.com", "DNSKEY")] = _response(
        "example.com", "DNSKEY", [{"flags": 256, "key_tag": 1}]
    )
    fake_dns[("example.com", "DS")] = _response("example.com", "DS", [])
    status = dnssec_mod.check_dnssec("example.com")
    assert status.signed_evidence == "partial"


def test_asn_lookup_parses_cymru(fake_dns):
    qname = "34.216.184.93.origin.asn.cymru.com"
    fake_dns[(qname, "TXT")] = _response(
        qname, "TXT", [{"text": "15169 | 93.184.216.0/24 | US | arin | 2008-03-14"}]
    )
    info = asn_mod.asn_lookup("93.184.216.34")
    assert info.asn == "15169"
    assert info.prefix == "93.184.216.0/24"
    assert info.country == "US"
    assert info.registry == "arin"
    assert info.error is None


def test_asn_lookup_failure_graceful(fake_dns):
    from aegisforge.domain.dns_client import DNSError

    qname = "1.2.0.192.origin.asn.cymru.com"
    fake_dns[(qname, "TXT")] = DNSError("nope")
    info = asn_mod.asn_lookup("192.0.2.1")
    assert info.error is not None
    assert info.asn is None


def test_asn_lookup_ipv6_name():
    name = asn_mod._cymru_name("2001:db8::1")
    assert name.endswith(".origin6.asn.cymru.com")
    assert name.startswith(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2."
    )


def test_asn_lookup_bad_ip():
    info = asn_mod.asn_lookup("not-an-ip")
    assert info.error is not None
