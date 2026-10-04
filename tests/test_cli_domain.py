"""Tests for the domain CLI surface (network fully mocked)."""

import json

import pytest

from aegisforge.cli.main import main
from aegisforge.core.results import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from aegisforge.domain import dns_client as dns_client_mod
from aegisforge.domain import investigate as investigate_mod
from aegisforge.domain.dns_client import DNSRecord, DNSResponse
from aegisforge.domain.investigate import DomainOptions, InvestigationReport


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGISFORGE_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AEGISFORGE_AUDIT_LOG", str(tmp_path / "audit.log"))


def _patch_dns(monkeypatch, answers=()):
    records = [
        DNSRecord(name="example.com", rtype="MX", ttl=300, data=data)
        for data in answers
    ]
    response = DNSResponse(qname="example.com", qtype="MX", rcode=0, answers=records)
    monkeypatch.setattr(dns_client_mod, "query", lambda *a, **k: response)
    return response


def test_domain_dns_human_output(monkeypatch, capsys):
    _patch_dns(
        monkeypatch,
        [{"preference": 10, "exchange": "mail.example.com"}],
    )
    code = main(["domain", "dns", "example.com", "--type", "MX"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "example.com/MX: 1 record(s)" in out
    assert "mail.example.com" in out


def test_domain_dns_json_output(monkeypatch, capsys):
    _patch_dns(monkeypatch, [{"preference": 10, "exchange": "mail.example.com"}])
    code = main(["domain", "dns", "example.com", "--type", "mx", "--json"])
    assert code == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["command"] == "domain dns"
    assert data["data"]["records"][0]["detail"] == "10 mail.example.com"


def test_domain_dns_csv_output(monkeypatch, capsys):
    _patch_dns(monkeypatch, [{"preference": 10, "exchange": "mail.example.com"}])
    code = main(["domain", "dns", "example.com", "--type", "MX", "--csv"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "name,rtype,ttl,detail" in out
    assert "mail.example.com" in out


def test_domain_dns_bad_type(monkeypatch, capsys):
    code = main(["domain", "dns", "example.com", "--type", "PTR"])
    assert code == EXIT_ERROR


def test_domain_dns_query_failure(monkeypatch, capsys):
    def boom(*a, **k):
        raise dns_client_mod.DNSError("no route")

    monkeypatch.setattr(dns_client_mod, "query", boom)
    code = main(["domain", "dns", "example.com", "--type", "A"])
    assert code == EXIT_ERROR
    assert "no route" in capsys.readouterr().err


def _patch_investigate(monkeypatch):
    report = InvestigationReport(
        domain="example.com",
        dns={"records": {"A": []}},
        tls={
            "error": None,
            "days_until_expiry": 5,
            "not_after": "2026-10-07T00:00:00Z",
            "hostname_verified": True,
            "san_dns_names": ["example.com"],
        },
    )
    monkeypatch.setattr(
        investigate_mod, "investigate_domain", lambda domain, options: report
    )
    return report


def test_domain_investigate_human_output(monkeypatch, capsys):
    _patch_investigate(monkeypatch)
    code = main(["domain", "investigate", "example.com"])
    assert code == EXIT_FINDINGS  # expiring cert -> medium finding
    out = capsys.readouterr().out
    assert "domain investigation of example.com" in out
    assert "Findings:" in out
    assert "expires in 5 day(s)" in out


def test_domain_investigate_json_envelope(monkeypatch, capsys):
    _patch_investigate(monkeypatch)
    code = main(["domain", "investigate", "example.com", "--json"])
    assert code == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    assert data["command"] == "domain investigate"
    assert data["target"] == "example.com"
    assert data["data"]["domain"] == "example.com"
    assert len(data["findings"]) >= 1


def test_domain_investigate_rejects_ip(monkeypatch, capsys):
    code = main(["domain", "investigate", "93.184.216.34"])
    assert code == EXIT_ERROR
    assert "not an IP address" in capsys.readouterr().err


def test_domain_investigate_flags(monkeypatch):
    seen = {}

    def fake_investigate(domain, options):
        seen["options"] = options
        return InvestigationReport(domain=domain)

    monkeypatch.setattr(investigate_mod, "investigate_domain", fake_investigate)
    code = main(
        [
            "domain",
            "investigate",
            "example.com",
            "--no-rdap",
            "--no-whois",
            "--no-web",
            "--no-tls",
            "--resolver",
            "1.1.1.1",
        ]
    )
    assert code == EXIT_OK
    options = seen["options"]
    assert isinstance(options, DomainOptions)
    assert options.resolver == "1.1.1.1"
    assert options.rdap is False
    assert options.whois is False
    assert options.web is False
    assert options.tls is False
